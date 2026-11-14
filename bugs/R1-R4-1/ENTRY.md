## R1-R4-1

**Title.** Machine creation accepts a reproducible Keccak-256 configuration with a non-pristine uarch (uarch RAM image, uarch registers), so native interpretation runs while the uarch traps and the uarch-level claim builder refuses the machine.

**Severity.** High (preferred reading: R4's configuration clause binds creation, and the effect is a divergence between paths only at demonstrably unreachable states). Critical under the reading that accepting the configuration is itself an R4 violation on the honest operator's path that the High case does not absorb. Out of scope or Low under the first reviewer's reading (a deliberate, documented use of a unit-test facility by the trusted caller).

The first reviewer refuted this candidate as Out of scope. It applied the exclusion "The effect of a deliberate state change made through the machine API, when the API performs it as documented", because the manual documents `uarch.ram.backing_store.data_filename` ("typically left blank (other than in unit tests)"). It also read "this rule" in R4's configuration clause as met vacuously, since a non-pristine uarch is not a valid template. A second-opinion reviewer overturned that. R4 says "Every reproducible configuration that the emulator accepts, using the deployment's hash function and holding only register values that the RISC-V specification and the manual allow, yields a machine on which this rule holds. A configuration that would not is rejected when the machine is created." The clause names its own exemptions (unreproducible, another hash function, disallowed register values), and a uarch RAM image is not among them. Those three exemptions restate valid-template conditions; under the vacuous reading they would be redundant and the clause would have no content. The deliberate-change exclusion cannot excuse accepting a configuration that a specific rule says creation must reject, or "Every ... configuration that the emulator accepts" would never bind a documented configuration field. The valid-template definition also relies on creation-time checks ("created from a configuration, without disabling any of the emulator's consistency checks").

### Problem

`cartesi.machine(config)` accepts reproducible Keccak-256 configurations whose uarch is not pristine:

- `uarch.ram.backing_store.data_filename` pointing to any file is loaded into uarch RAM unchecked;
- `uarch.processor.registers` (`pc`, `cycle`, `halt`, `x1`..`x31`) are written unchecked.

On such a machine, native `run(1)` reaches mcycle 1, but with a junk uarch image `log_step_uarch` fails ("illegal instruction"), and with either change `collect_uarch_cycle_root_hashes` refuses ("microarchitecture is not pristine"). The honest operator then cannot compute uarch-level claims or log uarch steps from the template it created, while its mcycle-level claims (native) proceed. In a dispute that descends to the uarch level, the honest claim cannot be defended (section 1, completeness failure). Only `cartesi-machine --assert-rolling-template` checks the uarch node; creation does not.

R4 requires that every reproducible configuration the emulator accepts, with the deployment's hash function and allowed register values, yields a machine on which honest completeness holds, and that any other such configuration is rejected at creation.

### Component, role and area

Machine creation from a configuration (machine API, AUDIT.md row 2: "Honest operator where a production validator node plausibly calls it on the honest operator's path", here "Obtaining its valid template" for a template the operator produces). The paths that then fail are the uarch program and `collect_uarch_cycle_root_hashes` (AUDIT.md row 1: Honest operator). Area: creation-time consistency checks of the uarch state.

### Location

- `src/machine-address-ranges.cpp` `machine_address_ranges::push_back_uarch_ram`: copies the embedded pristine image only when the backing store is newly created; a configured `data_filename` is used as is.
- `src/machine.cpp` `machine::init_uarch_processor`: writes `uarch.processor.registers` from the configuration without checking them against the pristine reset state.
- `src/machine.cpp` (`collect_uarch_cycle_root_hashes`, `log_step_uarch`): refuse or trap later, after creation has accepted the machine.

### Evidence and test

`bugs/R1-R4-1/test.lua` (run with `bugs/run.sh R1-R4-1`, under a second) creates machines from reproducible Keccak-256 configurations whose RAM is the harness bare-metal guest `accept.bin`: a control with the default uarch, a uarch RAM image of 4 KiB of `0xff` bytes, and `uarch.processor.registers.pc = 0x600004`. For each, the requirement holds if creation raises, or if `collect_uarch_cycle_root_hashes(1)` and `log_step_uarch()` succeed and the uarch-path hash at mcycle 1 equals the native `run(1)` root hash. Re-run by the second-opinion reviewer on audit/prt2:

```
control (default uarch): accepted (uarch node pristine=true); native run(1): ok (mcycle 1); collect_uarch_cycle_root_hashes(1): ok; log_step_uarch: ok; uarch path agrees with native at mcycle 1
VIOLATED: R4 configuration clause: uarch.ram.backing_store.data_filename = 4 KiB of 0xff: accepted (uarch node pristine=false); native run(1): ok (mcycle 1); collect_uarch_cycle_root_hashes(1): error: microarchitecture is not pristine; log_step_uarch: error: illegal instruction
VIOLATED: R4 configuration clause: uarch.processor.registers.pc = 0x600004 (aligned, inside uarch RAM): accepted (uarch node pristine=false); native run(1): ok (mcycle 1); collect_uarch_cycle_root_hashes(1): error: microarchitecture is not pristine; log_step_uarch: ok
run.sh: R1-R4-1: exit 1 (bug present)
```

The uarch RAM image case alone is enough. The register case counts only if a uarch `pc` of that value is a register value "that the RISC-V specification and the manual allow"; the manual places no constraint on uarch register values. Found, proved and reviewed on Opus 5.5; no fallback model was used.

### Trigger and reachability

The trusted creator of a template writes a configuration that sets the uarch RAM image or uarch registers, a field the manual documents. No guest can produce the state: a valid template has a pristine uarch ("at an mcycle boundary, with the uarch in its pristine reset state"), the guest cannot address uarch state or uarch memory (R8), native interpretation never writes uarch state, and every mcycle of the uarch path ends with the uarch reset, which restores the pristine uarch. So no input sequence from any valid template reaches a non-pristine uarch at an mcycle boundary, and the divergence occurs only at demonstrably unreachable states. The defect is that creation lets a trusted configuration start there, which R4's configuration clause forbids.

### Rating

1. Out of scope: no, under the preferred reading. "The effect of a deliberate state change made through the machine API, when the API performs it as documented" does not cover what R4's configuration clause regulates: "Every reproducible configuration that the emulator accepts, using the deployment's hash function and holding only register values that the RISC-V specification and the manual allow, yields a machine on which this rule holds. A configuration that would not is rejected when the machine is created." The clause lists its exemptions, and a uarch image is not one. The snapshot exclusions do not apply (creation, not loading).
2. Role: machine creation, "Honest operator where a production validator node plausibly calls it on the honest operator's path" (AUDIT.md row 2), and the uarch program and `collect_uarch_cycle_root_hashes`, Honest operator (row 1). Section 3: the honest operator role covers "the transition function, its log producers, the computation-hash builders".
3. High and Medium cases: "A divergence between paths only at demonstrably unreachable states." Native interpretation reaches mcycle 1 while the uarch path traps or is refused, at a state no valid template reaches (argument above). High.
4. Critical: not reached under the preferred reading, since step 3 fits first. Under the alternative reading, accepting the configuration violates R4's configuration clause while "Obtaining its valid template" on the honest operator's path, which section 8 makes Critical.

Readings: High (preferred) / Critical (if the creation-time acceptance is itself rated as an R4 violation on the honest operator's path) / Out of scope or Low (if R4's clause is vacuous for configurations that are not valid templates, or if configuring a documented unit-test field is "misuse of an API by its trusted caller"). The deciding facts are whether R4's configuration clause lists all exemptions creation may rely on (then a non-pristine uarch must be rejected), and whether production template builders ever pass uarch fields in a configuration.

### Possible solution and risks

At creation of a reproducible machine (and, for consistency, on load without `clear_hash_tree` where the config is trusted), reject a configuration whose uarch RAM image or uarch registers differ from the pristine reset state, for example by checking that the uarch state node hash equals `UARCH_PRISTINE_STATE_HASH` after construction. Keep the unit-test facility behind an explicit opt-in flag, and refuse that flag for reproducible machines intended as templates, or record it in the hashed state so the template cannot be mistaken for a valid one. Risk: unit tests that load custom uarch programs into reproducible machines need the opt-in; the check adds one node-hash comparison at creation.

### Risk of not fixing it

A template whose configuration carries a stale or custom uarch image, or uarch registers copied from another machine, is accepted and committed on-chain. Its mcycle-level claims compute normally, so the problem shows only when a dispute descends to the uarch level, where the honest operator cannot build uarch-level claims or step logs and loses by timeout. Only the trusted template creator can trigger it. Mitigation outside the code: run `cartesi-machine --assert-rolling-template` (which checks the uarch node) on every template before committing its hash.
