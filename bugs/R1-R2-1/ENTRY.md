## R1-R2-1

**Title.** `write_reg("iunrep", ...)` changes the hashed unreproducible-mode register while every guard reads the config copy, and `store` then writes a directory that refuses to load

**Severity.** Medium

### Problem

The unreproducible mode is kept in two places: the hashed shadow register `iunrep` and the copy in the machine's
configuration (`m_c.processor.registers.iunrep`). Every behavior that depends on the mode reads the config copy.
That includes the uarch refusal, the refusals of `collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`,
the `store` refusal, and host interrupt polling. The two copies are compared only when a machine is created or
loaded. `machine::write_reg` refuses writes to the machine-ID registers (`mvendorid`, `marchid`, `mimpid`), which
the same load-time check binds to the configuration. It has no such guard for `iunrep`.

After `write_reg("iunrep", 1)` on a reproducible machine, the root hash commits to an unreproducible machine. The
machine still runs, logs uarch steps, collects computation hashes and stores. `store` writes the shadow state with
`iunrep = 1` next to a `config.json` with `"iunrep":0`. Loading that directory fails with "iunrep mismatch between
shadow state and config". The reverse write (0 on an unreproducible machine) produces a hash that says reproducible
while the machine refuses the uarch and the collectors.

This violates R2: "Every register and every configuration value that affects a transition has one source of truth in
the hashed state, and every path reads it from there." It also contradicts the manual, which calls `iunrep` "a
creation-time mode", and R14: "The unreproducible mode is fixed at creation and recorded in the hashed state." No
valid template and no honest-operator operation reaches the split state, so the goal of section 1 is not affected.
The defect is a machine API operation, used as documented, that leaves the machine's cached state and its stored
directory inconsistent with its contents.

### Component, role and area

- `machine::write_reg` belongs to "the rest of the machine API (C, Lua and JSON-RPC)". A production validator node
  does not plausibly write `iunrep` on the honest operator's path, so this use is off that path.
- The guarded paths (uarch, collectors, `store` and load) belong to "interpreter, state-access layers, ..., and
  storing, loading, cloning and syncing machines", which is the honest-operator role. They behave correctly on every
  machine where the two copies agree, and the copies always agree unless `write_reg("iunrep")` was called.
- Area: the source of truth for the unreproducible mode, and its consistency between the machine and a stored
  directory.

### Location

- `src/machine.cpp`, `machine::write_reg`, `case reg::iunrep:` (around line 1444). It writes
  `m_s->shadow.registers.iunrep` with no read-only check. Compare `case reg::mvendorid` / `marchid` / `mimpid`
  (around lines 1354-1359), which throw "register is read-only".
- `src/machine.hpp`, `machine::is_unreproducible()` (around line 857). It returns
  `m_c.processor.registers.iunrep != 0`, which is the config copy.
- `src/machine.cpp`, callers of `is_unreproducible()`: `store` (around line 430), uarch (around line 2194),
  `poll_external_interrupts` (around line 2348), and the collectors (around lines 2445, 2619, 2770).
- `src/machine.cpp`, `validate_processor_shadow` (around lines 222-224). It is the only comparison of the two copies,
  and it runs at create and load only.

### Evidence and test

`bugs/R1-R2-1/` contains `test.lua` and `README.md`. The test uses the shared harness configuration
`baremetal-minimal`, a reproducible bare-metal machine. It first checks, as a control, that `log_step_uarch` works on
a fresh copy of the machine. It then calls `write_reg("iunrep", 1)`. It exits 0 in either of two cases:

- the write is refused;
- every path follows the hashed register: `log_step_uarch` refuses, and `store` either refuses or writes a directory
  that loads back with the same root hash and `iunrep`.

Run with `bugs/run.sh R1-R2-1`. It takes about a second. On audit/prt2 it prints the following and exits 1. The
prover ran it three times and the reviewer twice more, with the same result every time.

```
write_reg('iunrep', 1) accepted; read_reg('iunrep') = 1; root hash changed: true
VIOLATION: log_step_uarch succeeded on a machine whose hashed iunrep is 1 (the guard reads the config copy, not the hashed register)
store succeeded
VIOLATION: store wrote a directory that refuses to load: .../bugs/R1-R2-1/test.lua:75: iunrep mismatch between shadow state and config
VIOLATED: R2/R14: iunrep must have one source of truth in the hashed state (write refused, or every path follows it)
run.sh: R1-R2-1: exit 1 (bug present)
```

The reviewer also checked two facts by hand. After the write, `run` and `collect_mcycle_root_hashes` still succeed.
The stored `config.json` holds `"iunrep":0` while the stored shadow holds 1. Either fix in "Possible solution" makes
the test exit 0. The test was not modified. No fallback model was used.

### Trigger and reachability

Only a trusted caller of the machine API triggers it, by calling `write_reg("iunrep", v)` with `v` different from
the configured value, locally or over JSON-RPC. No guest action triggers it. R8 makes `iunrep` unreachable from guest
memory accesses, and no instruction writes it: the interpreter never calls `write_iunrep`. No input triggers it
either, because delivery does not touch `iunrep`.

A valid template is "created from a configuration ... and changed only by running it and delivering inputs", so its
two copies always agree. Every machine the honest operator stores, loads, clones or syncs therefore keeps them in
agreement. The split state is reachable only through this API call, and the honest-operator path never makes it.

### Rating

1. Out of scope. The exclusions checked are these.
   - "The effect of a deliberate state change made through the machine API, when the API performs it as documented
     (section 4)." This clause covers the component (`write_reg` is a machine API operation), but it does not cover
     the defect. The documented effect is that the register changes ("The value of any register can be changed with
     the `machine:write_reg` ... method"). That effect, the hash now committing to `iunrep = 1`, is out of scope. The
     emulator's own copy of the mode then disagreeing with the register, and `store` writing a directory its own
     `load` refuses, are not documented effects of the write. The Medium case quoted in step 3 is written for exactly
     such a documented API use, and it would be empty if this exclusion swallowed it.
   - "Defects that need an untrusted party to call the machine API directly" does not apply: the caller is trusted.
   - The exclusion for snapshots the emulator did not write does not apply: the emulator wrote this directory.
   - The O2 exclusion does not apply: there is no stop and no sharing.
2. Role. `write_reg` is "the rest of the machine API", which is honest operator only "where a production validator
   node plausibly calls it on the honest operator's path". No node writes `iunrep`, so this use is off the path. The
   paths that show the inconsistency (`store`/load, uarch, collectors) are honest operator. Section 3 says they play
   this role "within the limits of O1 and O2", and they misbehave only on a machine that the off-path call produced.
3. High and Medium cases. Section 8 Medium: "A machine API operation off the honest operator's path that, used as
   documented, leaves the hash tree, the cached state of the machine or a stored directory inconsistent with the
   machine's contents (R9)." This clause covers the component. `write_reg` is off the path and used as documented
   ("The value of any register can be changed"). It leaves the cached config copy that every guard reads
   inconsistent with the hashed register, and `store` then writes a directory whose `config.json` disagrees with its
   shadow state and does not load. The manual contradiction points the same way: "A contradiction between the manual
   and the behavior on a security-relevant point ... takes the severity it would have if the manual were right." The
   manual calls `iunrep` "a creation-time mode", and R14 says "fixed at creation". No High case applies, since the
   state is not reached by any input sequence from a valid template and no verifier or honest path diverges on a
   reachable state.
4. Critical. Not reached, because step 3 matched. R2 ("one source of truth in the hashed state, and every path reads
   it from there") is violated structurally. But it is observable only after the off-path API write, never at a
   reachable state or on the honest operator's path.

Other readings:

- **Low.** "A failure that needs misuse of an API by its trusted caller". Writing a register the manual calls
  "creation-time" could be called misuse. The deciding fact is whether the manual's general statement that any
  register can be written counts as documenting writes to `iunrep`. The code refuses the analogous machine-ID
  registers, and the manual does not list `iunrep` as read-only. On that text the write is documented use, so Medium
  is the better-supported reading.
- **Out of scope.** If the first exclusion is read to cover every consequence of a documented write, including the
  emulator's own inconsistency, the defect is out of scope. That reading would empty the Medium case above, so it is
  not preferred.

### Possible solution and risks

The preferred fix makes `iunrep` read-only to the host. `write_reg(reg::iunrep, ...)` would throw "register is
read-only", as for `mvendorid`/`marchid`/`mimpid`. `init_processor` would write the configured value straight into
the shadow, as it already does for the machine-ID registers. The manual's `write_reg` paragraph would list the
read-only registers. Risk: any tool or test that writes `iunrep` after creation breaks. That use is unsupported in any
case, because such a machine cannot be stored and reloaded.

An alternative or addition is to have `is_unreproducible()` read the shadow register, so that there is a single
source of truth. Risk: the VirtIO devices and the TTY setup are fixed at creation from the config, so a machine whose
register flips to 0 would keep host devices while it claims to be reproducible. Read-only is the safer fix.

### Risk of not fixing it

A trusted caller (a development tool, a debugger, a test script, or a careless integration) that writes `iunrep` gets
a machine whose hash claims one mode while it behaves as the other. It can keep computing hashes and storing, and the
stored directory then cannot be loaded. Untrusted parties and guests cannot trigger it, and the honest operator's path
never writes `iunrep`, so the security goal is not exposed. Mitigation outside the code: never call `write_reg` on
`iunrep`.
