# R1-R2-1: `write_reg("iunrep")` splits the unreproducible mode into two sources of truth

## What is asserted

On a reproducible machine (`baremetal-minimal` configuration of the shared harness), the test calls
`m:write_reg("iunrep", 1)`. The threat model requires one of two outcomes:

- the write is refused, because the mode is fixed at creation; or
- the write succeeds and every path then follows the hashed register. That means `log_step_uarch` refuses, as it
  does on any unreproducible machine, and `store` either refuses or writes a directory that loads back with the
  same root hash and `iunrep`.

As a control, `log_step_uarch` is first checked to work on an untouched copy of the reproducible machine.

## Requirements

- THREAT_MODEL R2: "Every register and every configuration value that affects a transition has one source of truth
  in the hashed state, and every path reads it from there."
- THREAT_MODEL R14: "The unreproducible mode is fixed at creation and recorded in the hashed state."
- THREAT_MODEL section 8, Medium: "A machine API operation off the honest operator's path that, used as documented,
  leaves the hash tree, the cached state of the machine or a stored directory inconsistent with the machine's
  contents (R9)."
- Manual (doc/README.md, register list): "Register `iunrep` is non-zero in machines configured as unreproducible,
  a creation-time mode ...". The same manual also says that "the value of any register can be changed with
  `machine:write_reg`". The reviewer has to settle that tension when scoping.

## Defect

- `machine::write_reg`, case `reg::iunrep` (src/machine.cpp), writes the shadow (hashed) register without the
  read-only check that `mvendorid`, `marchid` and `mimpid` have.
- `machine::is_unreproducible()` (src/machine.hpp) reads the config copy `m_c.processor.registers.iunrep`.
- Only `validate_processor_shadow` compares the two copies, and it runs only at create and load.

## Run

```sh
bugs/run.sh R1-R2-1
```

It takes about a second.

## Expected output on audit/prt2

```
write_reg('iunrep', 1) accepted; read_reg('iunrep') = 1; root hash changed: true
VIOLATION: log_step_uarch succeeded on a machine whose hashed iunrep is 1 (the guard reads the config copy, not the hashed register)
store succeeded
VIOLATION: store wrote a directory that refuses to load: ...: iunrep mismatch between shadow state and config
VIOLATED: R2/R14: iunrep must have one source of truth in the hashed state (write refused, or every path follows it)
run.sh: R1-R2-1: exit 1 (bug present)
```

Exit status 1. The test exits 0 if `write_reg("iunrep", ...)` is refused, or if `is_unreproducible()` reads the
hashed register and so makes the uarch and `store` refuse. It exits 2 on setup errors.

The test does not check the reverse direction: writing 0 to an unreproducible machine lets `collect_*` refuse while
the hash says the machine is reproducible. Either fix above changes that direction too.
