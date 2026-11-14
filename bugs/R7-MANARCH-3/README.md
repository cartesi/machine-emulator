# R7-MANARCH-3: uarch loads outside the documented uarch memory map return 0 on every path

## What is asserted

Before-state: `baremetal-minimal` at mcycle 0. Uarch RAM 0x600000 holds `ld x5, 0(x6)`, and `uarch_pc` = 0x600000
(a non-pristine uarch, built with `write_memory`/`write_reg`).

**(A) Loads from holes.** In these cases x6 is 0x8000, 0x90000000, 0x1000000000 or 0xfffffffffffffff8. The test checks
at run time that `get_address_ranges()` covers none of these addresses. None is uarch RAM either. The manual's uarch
memory map is "all memory ranges and devices visible to the main processor" plus the private uarch RAM, and it does
not include these addresses. The load is therefore a uarch trap. The test requires four refusals:

- `run_uarch(1)` refuses the step;
- `log_step_uarch` refuses it;
- the C++ replay verifier (`verify_step_uarch`) refuses a hand-built log of the step;
- the regenerated machine-solidity-step (`StepVerifier.step`, the referee verifier) refuses the same log. The test
  installs it with `anvil_setCode` on a private anvil, on a random port in 20000-29999, and stops that anvil at the
  end. This is the method of `bugs/R1-R10-1`.

The load address is the logged x6 value plus the immediate of the logged instruction word, so the log authenticates
the condition.

**(B) Load from a device address.** The test sets `htif_tohost` = 0x0101000000000041 and x6 = 0x40008000 (HTIF tohost,
a device visible to the main processor). One of two outcomes must hold:

- the load yields the device register, as the manual's map says;
- it is refused on every path, as a narrower and documented map would require.

A load that yields 0 matches neither. For comparison, the test also loads the same register from its shadow address
0x330.

**Control.** A load from uarch RAM 0x600100 must succeed natively. Both verifiers must accept the hand-built log with
the native after-hash. This check validates the log crafting; if it fails, the test exits 2.

The store half of this mismatch (verifiers accept stores that the native uarch refuses) is R1-R10-1, and this test
does not re-prove it.

## Requirement

Manual, doc/README.md, "The microarchitecture":

> code running in the uarch has access to the entire state of the Cartesi Machine, including the main processor and
> the entire board.
>
> In addition to being able to access all memory ranges and devices visible to the main processor, the uarch includes
> a private 2MiB of RAM.

THREAT_MODEL.md, R3:

> The uarch traps when it executes an instruction it does not implement, an environment call it does not define or
> with arguments that call does not accept, an access that its memory map does not allow, or an abort it executes
> deliberately. [...] Running the uarch natively, the computation-hash builders and the log producers refuse every
> uarch trap instead of defining a successor. A verifier refuses a trap whenever the log it receives already
> authenticates the condition.

THREAT_MODEL.md, section 8: "A contradiction between the manual and the behavior on a security-relevant point is a
defect in one of the two."

## How to run

```sh
bugs/run.sh R7-MANARCH-3
```

The test needs four things:

- the in-tree emulator;
- `bugs/harness/work/configs/baremetal-minimal`;
- foundry (`anvil`, `cast`), `jq` and `curl`;
- the StepVerifier artifact `bugs/harness/work/evm/out/StepVerifier.sol/StepVerifier.json`.

It takes about 1 s.

## Expected output on audit/prt2 (exit 1)

```
control: uarch RAM 0x600100          native: x5=0x1122334455667788 | C++ verify: accepted (= native) | EVM: accepted (= native)
hole 0x8000                          run_uarch: DEFINED SUCCESSOR, x5=0x0
                                     log_step_uarch: LOGGED A SUCCESSOR
                                     C++ verify_step_uarch: ACCEPTED, after-hash 8366af04...c7af
                                     EVM StepVerifier.step: ACCEPTED, after-hash 8366af04...c7af
hole 0x90000000                      (same: defined successor, logged, both verifiers accept)
hole 0x1000000000                    (same)
hole 0xfffffffffffffff8              run_uarch: DEFINED SUCCESSOR, x5=0x0
                                     log_step_uarch: LOGGED A SUCCESSOR
                                     C++ verify_step_uarch: ACCEPTED, after-hash 4f2b7ff0...b541
                                     EVM StepVerifier.step: rejected (execution reverted: panic: assertion failed (0x01) ...)
HTIF tohost device 0x40008000        htif_tohost = 0x101000000000041; LD from its shadow 0x330 gives 0x101000000000041
                                     run_uarch: x5=0x0 (NOT the device register)
                                     log_step_uarch: logged; C++ verify of that log: accepted
VIOLATED: R3 + manual uarch memory map: ... 16 violation(s) of 17 checks
run.sh: R7-MANARCH-3: exit 1 (bug present)
```

The output also shows a path divergence that this test does not assert separately. For a load at 0xfffffffffffffff8,
native execution, the log producer and the C++ verifier all define the successor x5 = 0. The EVM step reverts with a
Solidity assertion panic, presumably an overflow check on the word address.

The test exits 0 once both of the following hold:

- every path refuses the hole loads;
- the device load yields the register, or every path refuses it.

The before-states have non-pristine uarch RAM and registers. They are built through the machine API, not reached
from a valid template.
