## R3-VARSHADOW-1

**Title.** The guard that keeps HTIF getchar out of reproducible machines runs only at create and load. After `write_reg("htif_iconsole", ...)` or a full-shadow `write_memory`, native interpretation diverges from the uarch and `collect_mcycle_root_hashes`, and `store` writes a directory that `load` refuses

**Severity.** High (preferred reading). Medium under the reading of the confirmed precedent R1-R2-1. Out of scope or Low under a broad reading of the deliberate-change exclusion (see Rating).

### Problem

`machine::init_console` refuses a reproducible machine whose hashed `htif_iconsole` register has the GETCHAR bit set,
or whose runtime console input source is not `from_null` ("TTY stdin is only supported in unreproducible machines").
It runs only when a machine is created or loaded. Three later API operations bypass it, and the emulator accepts all
three on a reproducible machine:

- `write_reg("htif_iconsole", v)` with no check;
- `write_memory` of the full processor shadow, where `validate_processor_shadow` does not look at `iconsole`;
- `set_runtime_config{console={input_source=...}}`, which reconfigures the console with no reproducibility check (on
  its own it has no effect on the state, because no getchar is served while the GETCHAR bit is clear).

Once the bit is set, a guest GETCHAR request (`tohost` = console, cmd 0) is answered differently by the
implementations of the transition function:

- Native interpretation (`state_access::do_getchar`) always asks the host console. With the default `from_null`
  source the input is closed, so it returns EOT (4) and writes `fromhost` DATA = 5. With `from_buffer` it returns the
  host's bytes ('A' gives 0x42, 'Z' gives 0x5b).
- The uarch and the non-interactive state accesses used by `collect_mcycle_root_hashes` and the log producers
  (`device_state_access::do_getchar` with a non-interactive access) return -1, so they write DATA = 0.

The native run and the uarch + reset therefore reach different root hashes at the same mcycle, from the same state,
with the default runtime configuration and no host input at all. This violates R2: "Wherever two of the following
reach the same position, they must agree on its canonical hash", for "Native interpretation", "The uarch running the
interpreter, plus the uarch reset" and "The computation-hash builders, whole or in parts". It also shows a runtime
option outside the hashed state changing a transition natively (R1: "No configuration, runtime option, or file
outside the hashed state, other than the referee parameters, may change any transition"; R2: "Every register and
every configuration value that affects a transition has one source of truth in the hashed state, and every path
reads it from there"), and the native interpreter reading host console input on a reproducible machine (R14).

`store` succeeds on such a machine (it checks only the config copy of `iunrep`), and the directory it writes holds the
GETCHAR bit in its shadow state, so loading it fails in `init_console`. A snapshot the emulator itself wrote does not
load.

The state is unreachable from any valid template (see Trigger and reachability), so the goal of section 1 is not
broken. The defect removes a margin the goal relies on: the transition function, which "The manual's documented
semantics define ... on every state", has two implementations that disagree on a state that a trusted API call can
produce, and the source code itself says (htif-address-range.cpp) that reaching this branch "in the blockchain"
would be "some serious bug".

### Component, role and area

- Diverging components: the interpreter and the state-access layers (native `state_access` vs the uarch and the
  non-interactive accesses of `collect_mcycle_root_hashes` and the log producers), and storing and loading machines.
  AUDIT.md table: "Interpreter, state-access layers, devices, uarch program, hash tree, log producers,
  `collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`, input delivery, and storing, loading, cloning
  and syncing machines" | "Honest operator".
- Triggering calls: `write_reg`, `write_memory` (full shadow) and `set_runtime_config`, which are "The rest of the
  machine API (C, Lua and JSON-RPC)" | "Honest operator where a production validator node plausibly calls it on the
  honest operator's path". No node writes `htif_iconsole` or the processor shadow on that path, so these uses are
  off it. A node may call `set_runtime_config` (for example for hash-tree concurrency), but a non-null input source
  has no effect without the GETCHAR bit.
- Area: HTIF console device semantics on reproducible machines; the source of truth for "console input enabled".

### Location

- `src/machine.cpp`, `machine::init_console` (around lines 351-358): the only check, called from the constructor
  (around line 325), so only at create and load.
- `src/machine.cpp`, `machine::write_reg`, `case reg::htif_iconsole:` (around line 1468): writes the shadow register
  with no check.
- `src/machine.cpp`, `machine::validate_processor_shadow` (from around line 205), used by the full-shadow
  `write_memory`: does not check `iconsole` against `iunrep`.
- `src/machine.cpp`, `machine::set_runtime_config` (around lines 415-424): reconfigures the console with no check.
- `src/state-access.hpp`, `state_access::do_getchar` (around line 541): native path, always calls
  `machine::getchar()` whatever the mode.
- `src/device-state-access.hpp`, `device_state_access::do_getchar` (around lines 153-158): returns `{-1, false}` for
  non-interactive accesses (uarch, collectors, log producers).
- `src/htif-address-range.cpp`, `htif_console` (around lines 93-117): writes `fromhost` DATA = c + 1.
- `src/machine-console.cpp`, `machine_console::getchars` (around line 82): returns EOT when input is closed
  (`from_null`).
- `src/machine.cpp`, `machine::store` (around line 430): checks only `is_unreproducible()` (config copy).

### Evidence and test

`bugs/R3-VARSHADOW-1/` contains `test.lua`, `README.md`, `getchar.S` (the source of the 32-byte bare-metal guest,
which the test embeds as hex: `tohost` <- console GETCHAR, `a0` <- `fromhost`, `tohost` <- halt, spin) and this entry.
The test builds a reproducible machine with 4 MiB of RAM holding the guest. Controls (printed, the second one
enforced as a setup check): creating a reproducible machine with the GETCHAR bit is refused, and without any trigger
native `run`, `run_uarch` + `reset_uarch` and `collect_mcycle_root_hashes` reach the same root hash at the halt.

For each of the triggers `write_reg('htif_iconsole', iconsole|GETCHAR)` and full-shadow `write_memory` with that bit,
it exits 0 if the trigger is refused, or if (a) the three paths reach the same root hash at the halt and (c) `store`
refuses or writes a directory that loads back with the same root hash. For `set_runtime_config` with
`input_source = "from_buffer"` it exits 0 if refused, or if (b) the root hash at the halt does not depend on the byte
given to `write_console_input` ('A' vs 'Z'); this part also tries the `write_reg` trigger and tolerates its refusal.

Run with `bugs/run.sh R3-VARSHADOW-1` (about 4 seconds). On audit/prt2 it prints (paths shortened) and exits 1:

```
create reproducible machine with GETCHAR enabled: refused: .../test.lua:84: TTY stdin is only supported in unreproducible machines
control (no trigger): native == uarch == collect at the halt
write_reg('htif_iconsole', iconsole|GETCHAR): accepted on a reproducible machine
  fromhost at halt: native 0x0100000000000005, uarch 0x0100000000000000, collect 0x0100000000000000
VIOLATION: write_reg('htif_iconsole', iconsole|GETCHAR): native and uarch+reset root hashes differ at the halt (R2)
VIOLATION: write_reg('htif_iconsole', iconsole|GETCHAR): native and collect_mcycle_root_hashes differ at the halt (R2)
  store succeeded; load refused: .../test.lua:124: TTY stdin is only supported in unreproducible machines
VIOLATION: write_reg('htif_iconsole', iconsole|GETCHAR): store wrote a directory that load refuses (R9)
write_memory(full shadow with iconsole|GETCHAR): accepted on a reproducible machine
  fromhost at halt: native 0x0100000000000005, uarch 0x0100000000000000, collect 0x0100000000000000
VIOLATION: write_memory(full shadow with iconsole|GETCHAR): native and uarch+reset root hashes differ at the halt (R2)
VIOLATION: write_memory(full shadow with iconsole|GETCHAR): native and collect_mcycle_root_hashes differ at the halt (R2)
  store succeeded; load refused: .../test.lua:124: TTY stdin is only supported in unreproducible machines
VIOLATION: write_memory(full shadow with iconsole|GETCHAR): store wrote a directory that load refuses (R9)
set_runtime_config{console={input_source='from_buffer'}}: accepted on a reproducible machine
  fromhost after host input 'A': 0x0100000000000042 (H=1); after 'Z': 0x010000000000005b (H=1)
VIOLATION: host console input reaches the hashed state of a reproducible machine (R14)
7 violation(s)
run.sh: R3-VARSHADOW-1: exit 1 (bug present)
```

The prover ran it four times and the reviewer three more, with exit 1 every time. The reviewer checked the facts in
the code listed under Location and did not modify the test. The test exits 0 under either fix in "Possible solution"
(refusing the triggers, or making every path ignore console input on a reproducible machine together with a
consistent store/load). No fallback model was used.

### Trigger and reachability

Only a trusted caller of the machine API triggers it, locally or over JSON-RPC, by setting the GETCHAR bit of
`htif_iconsole` with `write_reg` or a full-shadow `write_memory` on a reproducible machine. No guest or input
triggers it, and no input sequence from any valid template produces a state with the bit set:

- A valid template is "created from a configuration, without disabling any of the emulator's consistency checks, and
  changed only by running it and delivering inputs". `init_console` refuses the bit at creation and at load, so no
  valid template has it.
- Running cannot set it. The guest cannot address the shadow registers (R8), and the HTIF device accepts 64-bit
  writes only at `tohost` and `fromhost`; a write to the `iconsole` offset returns failure
  (`htif_address_range::do_write_device`). No instruction or device semantics writes `iconsole`.
- Delivery writes the rx buffer, `imcyclemax`, the revert root hash and the yield registers, not `iconsole`.

The runtime input source alone changes nothing on a reproducible machine without the bit (no getchar is served and
console input is not polled), so a node that only calls `set_runtime_config` is not affected.

### Rating

1. Out of scope. Exclusions checked:
   - "The effect of a deliberate state change made through the machine API, when the API performs it as documented
     (section 4)." This clause covers the trigger (`write_reg`/`write_memory` are machine API operations performing
     the write as documented: "The value of any register can be changed with the `machine:write_reg` ... method").
     On the preferred reading it covers only the effect of the change: the hashed register now has the GETCHAR bit
     and the guest's getchar requests are honored. It does not cover two implementations of the transition function
     then answering the same request on the same state differently (DATA = 5 natively, 0 in the uarch and the
     collectors, with no host input at all), nor `store` writing a directory its own `load` refuses. Those are
     emulator behaviors, not documented effects of the write. Reading the clause as covering every consequence would
     empty the Medium case "A machine API operation off the honest operator's path that, used as documented, leaves
     ..." quoted below. The part of the finding where host bytes from `write_console_input` reach the state is
     closer to the documented effect (the caller enabled console input and supplied the bytes through the API), so
     the rating does not rest on it.
   - "Defects that need an untrusted party to call the machine API directly": does not apply, the caller is trusted.
   - "Defects triggered only by loading a snapshot that the emulator did not write ...": does not apply, the emulator
     wrote the directory.
   - "Nondeterminism in unreproducible machines (R14)": does not apply, the machine is reproducible (`iunrep` = 0 in
     both copies).
   - O1/O2 exclusions: no adoption, no stop, no sharing.
2. Role. The diverging components are the interpreter, the state-access layers, `collect_mcycle_root_hashes`, the
   uarch, and storing and loading, which AUDIT.md lists as "Honest operator". Section 3: "The transition function,
   its log producers, the computation-hash builders, ... and storing, loading, cloning and syncing machines ... play
   this role in every deployment." This clause covers them. The triggering calls are "the rest of the machine API",
   off the honest operator's path for this use.
3. High and Medium cases.
   - Section 8 High: "A divergence between paths only at demonstrably unreachable states." This clause covers the
     honest-operator components above. Native interpretation and the uarch + reset (and the computation-hash builder)
     reach different hashes at the same mcycle from the same state, and that state is unreachable (argued under
     Trigger and reachability). The section 2 definition says the state transition function is defined by "The
     manual's documented semantics ... on every state", and "The uarch program and the verifier code that a
     deployment fixes on-chain must implement it"; the native interpreter departs from it here.
   - Section 8 Medium: "A machine API operation off the honest operator's path that, used as documented, leaves the
     hash tree, the cached state of the machine or a stored directory inconsistent with the machine's contents
     (R9)." It also matches in part: the guard reads only the creation-time state, and `store` writes a directory
     that `load` refuses. Strictly, the directory faithfully holds the contents (the refusal comes from `load`
     re-applying the guard), so this case fits less exactly than the High one.
   - Since the High case matches, the preferred class is High.
4. Critical. Not reached. R1, R2 and R14 are violated, but only at a state that no input sequence from a valid
   template produces and only after an off-path API write, never at a reachable state or on the honest operator's
   path.

Other readings, and the facts that decide:

- **Medium.** The campaign rated the analogous R1-R2-1 (`write_reg("iunrep")`, guards reading a creation-time copy,
  `store` writing an unloadable directory) Medium under the off-path API case. If the reader treats this finding as
  that same pattern and does not count the native-vs-uarch disagreement on an API-written state as a "divergence
  between paths", it is Medium. The deciding fact is whether the High case "divergence between paths only at
  demonstrably unreachable states" is meant to include states that only a machine API write produces. Native vs
  uarch divergence can only ever be exercised on such states (or on snapshots, which are excluded), which supports
  including them.
- **Out of scope / Low.** If "The effect of a deliberate state change" covers everything the machine does after the
  write, or if enabling getchar on a reproducible machine counts as "a failure that needs misuse of an API by its
  trusted caller" (the manual says "Verifiable computations must always be run in non-interactive sessions" and
  "external modifications to the state break the reproducibility of Cartesi Machines"), the finding is out of scope
  or Low. The manual does not list `htif_iconsole` as read-only, and the emulator refuses the same configuration at
  creation, so the write is documented use that bypasses a consistency check; that reading is not preferred.

### Possible solution and risks

Preferred: enforce the invariant wherever the state or the runtime configuration can change, not only at creation.
`write_reg(reg::htif_iconsole, v)` and the full-shadow `write_memory` (in `validate_processor_shadow`) refuse the
GETCHAR bit on a reproducible machine, and `set_runtime_config` refuses a non-null input source on one (or factor
`init_console` into a check called from all four places). Risk: tools or tests that enable getchar after creation on a
reproducible machine break; that use cannot be stored and reloaded today anyway.

Additionally or alternatively, make native `do_getchar` return `{-1, false}` on reproducible machines, matching the
uarch and the non-interactive accesses, so that the transition function has one definition on every state. Risk: if
done alone, `store` still writes a directory that `load` refuses; the load-time guard would also need to accept the
bit on reproducible machines (with getchar then answered "no character"), which changes documented behavior and
should be reflected in the manual. Either fix should keep reading the mode from a single source of truth (see
R1-R2-1).

### Risk of not fixing it

A trusted caller (a debugger, a development tool, a test script or a careless integration) that enables HTIF getchar
on a reproducible machine gets a machine whose native run disagrees with its uarch, its computation hashes and its
logs from the first getchar on, and whose stored directory cannot be loaded. A claim computed natively on such a
machine could not be proved. Guests, input senders and dishonest claimants cannot trigger it, and the honest
operator's path never writes `htif_iconsole`, so the security goal is not exposed. Mitigation outside the code: never
write `htif_iconsole` or the processor shadow on a reproducible machine.
