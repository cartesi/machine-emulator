# R3-VARSHADOW-1: HTIF console input enabled after creation on a reproducible machine

`machine::init_console` (src/machine.cpp) refuses the HTIF GETCHAR bit of the hashed `htif_iconsole` register, and
any non-null console input source, on a reproducible machine, but it runs only at create and load. Afterwards
`write_reg("htif_iconsole", ...)`, `write_memory` of the full processor shadow (validated by
`validate_processor_shadow`, which does not look at `iconsole`) and `set_runtime_config{console={input_source=...}}`
are accepted. A GETCHAR request then puts a host byte (5 from the null source, the host's bytes from a buffer) in
`fromhost` when interpreted natively, but 0 in the uarch and in `collect_mcycle_root_hashes` (non-interactive state
accesses). `store` succeeds and its directory refuses to load ("TTY stdin is only supported in unreproducible
machines").

## What is asserted

Requirements (THREAT_MODEL.md):

- R2: native interpretation, "The uarch running the interpreter, plus the uarch reset" and "The computation-hash
  builders" "must agree on its canonical hash"; "Every register and every configuration value that affects a
  transition has one source of truth in the hashed state, and every path reads it from there."
- R14: "In a reproducible machine, the host reaches the state only through deliveries and deliberate changes through
  the machine API. That rules out host devices, any other host input".
- R9 / section 8 Medium: "A machine API operation off the honest operator's path that, used as documented, leaves
  ... a stored directory inconsistent with the machine's contents".

For each trigger (write_reg, full-shadow write_memory) on a reproducible machine running `getchar.S` (console
GETCHAR, read fromhost, halt): either the trigger is refused, or (a) native `run`, `run_uarch`+`reset_uarch` and
`collect_mcycle_root_hashes` reach the same root hash at the halt, and (c) `store` refuses or writes a directory that
loads with the same root hash. For `set_runtime_config` with `input_source = "from_buffer"`: either refused, or (b)
the root hash at the halt does not depend on the bytes given to `write_console_input` ('A' vs 'Z').

Controls: creating a reproducible machine with GETCHAR enabled is refused (the guard exists), and without a trigger
all three paths agree. The guest binary (32 bytes) is embedded in the test as hex; `getchar.S` is its source.

## Run

```sh
bugs/run.sh R3-VARSHADOW-1        # ~4 s
```

## Expected output on audit/prt2

```
write_reg('htif_iconsole', iconsole|GETCHAR): accepted on a reproducible machine
  fromhost at halt: native 0x0100000000000005, uarch 0x0100000000000000, collect 0x0100000000000000
VIOLATION: ... native and uarch+reset root hashes differ at the halt (R2)
VIOLATION: ... native and collect_mcycle_root_hashes differ at the halt (R2)
  store succeeded; load refused: ... TTY stdin is only supported in unreproducible machines
VIOLATION: ... store wrote a directory that load refuses (R9)
write_memory(full shadow with iconsole|GETCHAR): accepted on a reproducible machine
  (same three violations)
set_runtime_config{console={input_source='from_buffer'}}: accepted on a reproducible machine
  fromhost after host input 'A': 0x0100000000000042 (H=1); after 'Z': 0x010000000000005b (H=1)
VIOLATION: host console input reaches the hashed state of a reproducible machine (R14)
7 violation(s)
run.sh: R3-VARSHADOW-1: exit 1 (bug present)
```

Exit 1 while the defect is present; exit 0 once the triggers are refused on reproducible machines (or every path
ignores console input there and store/load round-trips); exit 2 on setup errors.
