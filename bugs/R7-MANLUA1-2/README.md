# R7-MANLUA1-2: stored config.json / get_initial_config() of a loaded machine report creation-time registers

## What is asserted

For a machine loaded from a directory written by `machine:store()`, every register value in
`get_initial_config().processor.registers` equals `read_reg()` of the same loaded machine.

The manual (doc/README.md, "Persistent machines", about `machine:get_initial_config()` on a machine loaded from
`<directory>`):

> Note that this is *not* the configuration that was used to instantiate the machine for the first time, but rather
> the configuration used to instantiate a copy of the machine that was stored. [...] Likewise, the values of all
> registers will reflect the values as they were when stored.

Threat model, section 8: "A contradiction between the manual and the behavior on a security-relevant point is a
defect in one of the two. It takes the severity it would have if the manual were right." (Whether these config
fields are security-relevant is for the reviewer; the test only shows the contradiction.)

## Cause

`machine::store` (src/machine.cpp:520, `m_c.store(dir)`) writes the creation-time `machine_config` to
`config.json` without refreshing the register values from the machine's state, and `machine::get_initial_config`
(src/machine.cpp:405) returns that config. Only `iunrep` is cross-checked on load.

## Test

1. Case A: create from `bugs/harness/work/configs/baremetal-minimal/config.lua`, `run(1000)`, store to a temp dir,
   load, compare `mcycle` and `pc`.
2. Case B: load `bugs/harness/work/configs/baremetal-template/machine` (waiting at an accepted manual yield),
   deliver one advance-state input with `send_cmio_response`, store, load, compare `mcycle`, `pc`, `imcyclemax`,
   `iflags_Y`.

Exit 1 if any register differs, 0 if all agree, 2 on setup errors. Runs in a few seconds; the temp dir is removed.

```sh
bugs/run.sh R7-MANLUA1-2
```

## Expected output on audit/prt2

```
  A (create, run 1000, store, load): mcycle     get_initial_config()=0x0  read_reg()=0x3e8
  A (create, run 1000, store, load): pc         get_initial_config()=0x80000000  read_reg()=0x80000020
  B (template, deliver input, store, load): mcycle     get_initial_config()=0x0  read_reg()=0x35cee4
  B (template, deliver input, store, load): pc         get_initial_config()=0x80000000  read_reg()=0x800006b0
  B (template, deliver input, store, load): imcyclemax get_initial_config()=0xffffffffffffffff  read_reg()=0x100000035cee3
  B (template, deliver input, store, load): iflags_Y   0x0 (agree)
VIOLATED: manual: for a loaded machine, get_initial_config() register values reflect the values as they were when stored (5 register(s) differ from read_reg)
run.sh: R7-MANLUA1-2: exit 1 (bug present)
```

(`iflags_Y` agrees only by coincidence: 0 at creation and 0 again after the delivery. The shared stored
`baremetal-template` itself already reports `iflags.Y = 0` in its config while `read_reg("iflags_Y")` is 1.)
