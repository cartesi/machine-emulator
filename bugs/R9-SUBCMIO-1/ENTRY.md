## R9-SUBCMIO-1

**Title.** Machine creation accepts a reproducible Keccak-256 configuration that starts at a manual yield with the rx-rejected reason. Its revert root hash is 32 zero bytes, so the canonical hash at every later mcycle boundary is 0x00..00, the hash of no state, and no uarch-level claim or step proof can follow.

**Severity.** High (preferred: R4's configuration clause binds creation, and the effect is a divergence between paths only at demonstrably unreachable states, as for R1-R4-1). Critical under the reading that accepting the configuration is itself an R4 violation on the honest operator's path that no High case absorbs. Low under the reading that step 4 requires a reachable state or an honest-path operation, and that no honest operator ever creates a machine at a rejected yield.

### Problem

`cartesi.machine(config)` writes `processor.registers.iflags.Y` and `processor.registers.htif.tohost` from the configuration without checking them. A reproducible Keccak-256 configuration with `iflags.Y = 1` and `htif.tohost = (HTIF_DEV_YIELD << 56) | (HTIF_YIELD_CMD_MANUAL << 48) | (HTIF_YIELD_MANUAL_REASON_RX_REJECTED << 32)` is accepted. No configuration field sets the revert root hash, so it stays 32 zero bytes.

The rejection exception then applies to the new machine. The manual says of `collect_mcycle_root_hashes`: "When the manual yield rejected an input, the recorded revert root hash takes its place". The uarch reset and its log producer and verifier do the same. So the canonical hash at the next mcycle boundary, and at every later one, is 0x00..00. The rejecting machine is stuck: deliveries at a rejected yield are no-ops (R5). There is no "state to which the rejected input was delivered" for later mcycles to start from. The honest operator therefore cannot do the following.

- Compute the uarch-level claim of any later mcycle. `collect_uarch_cycle_root_hashes` refuses without a revert uarch tail ("revert uarch tail is required"). It also accepts any made-up tail whose last entry is 0x00..00, because it checks only that entry.
- Log a uarch step whose before-hash is the agreed leaf 0x00..00. Running the uarch on the machine it holds starts each later mcycle at the rejecting machine's root hash, not at 0x00..00.

So R4 fails on this machine, and in a dispute that reached those positions the honest claim could not respond (section 1, completeness failure). R4 says creation must reject such a configuration.

### Component, role and area

- Machine creation from a configuration. AUDIT.md row 2 ("Honest operator where a production validator node plausibly calls it on the honest operator's path") covers it as part of "Obtaining its valid template".
- The paths that then commit to 0x00..00 or cannot proceed. These are `collect_mcycle_root_hashes`, `collect_uarch_cycle_root_hashes`, and the uarch reset with its log producer and verifier. AUDIT.md row 1 makes them Honest operator.
- Area: creation-time consistency checks of the rollup registers (`iflags_Y`, `htif_tohost`) against the revert root hash.

### Location

- `src/machine.cpp` `machine::init_processor`. It writes `iflags_Y` and `htif_tohost` from the configuration and leaves the shadow's `revert_root_hash` zero.
- `src/machine.cpp` `machine::validate_processor_shadow`. It checks only `marchid`, `mvendorid`, `mimpid`, `x0`, `iunrep` and padding.
- `src/rejected-manual-yield.hpp` `is_rejected_manual_yield`. This is the predicate the substitution uses.
- `src/machine.cpp` `collect_mcycle_root_hashes` (around line 2538), `collect_uarch_cycle_root_hashes` (around lines 2803-2835 and 2944), and the reset-log path (around line 2305). Each substitutes `read_revert_root_hash()`. `src/uarch-reset-state.cpp` does the same.

### Evidence and test

`bugs/R9-SUBCMIO-1/` holds `test.lua` and `README.md`. Run the test with `bugs/run.sh R9-SUBCMIO-1`. It takes under a second.

The test creates two machines from reproducible Keccak-256 configurations with 1 MiB RAM, `iflags.Y = 1` and `tohost` set to a manual yield:

- A control with the rx-accepted reason. It must give a leaf and a reset after-hash equal to the root hash, or the test exits 2.
- The rx-rejected reason.

For the rejected case, the requirement holds if creation raises, or if both of the following are nonzero:

- the next-boundary leaf from `collect_mcycle_root_hashes`;
- the after-hash of `log_reset_uarch`/`verify_reset_uarch`.

The reviewer re-ran it three times on audit/prt2. Each run exited 1 with this output:

```
control (manual yield, accepted): accepted; root 26419c7c81fa7c26; revert root hash 0000000000000000; collect_mcycle_root_hashes leaf 26419c7c81fa7c26 (1 leaves); verify_reset_uarch after-hash 26419c7c81fa7c26; collect_uarch_cycle_root_hashes with made-up tail: n/a
VIOLATED: R4 configuration clause: iflags.Y=1, tohost = manual yield rx-rejected: accepted; root 4f44a2c7533d14f6; revert root hash 0000000000000000; collect_mcycle_root_hashes leaf 0000000000000000 (1 leaves); verify_reset_uarch after-hash 0000000000000000; collect_uarch_cycle_root_hashes with made-up tail: accepted; the canonical hash at the next mcycle boundary is 32 zero bytes, the hash of no state
VIOLATED: R4: a configuration whose machine cannot satisfy R4 must be rejected at creation
run.sh: R9-SUBCMIO-1: exit 1 (bug present)
```

The reviewer also checked the following with a separate script, which has since been deleted:

- On the rejected machine, `collect_uarch_cycle_root_hashes(mcycle + 1, 0, {})` fails with "revert uarch tail is required".
- A delivery leaves the machine unchanged (`iflags_Y` stays 1, same root hash).
- In each of two consecutive mcycles, running the uarch starts at root `4f44a2c7...` and its reset verifies to 0x00..00. So the uarch path never starts at the mcycle-level leaf.

Either fix makes the test exit 0: rejecting the configuration at creation, or never substituting a hash that is not a state's content hash. Found, proved and reviewed on Opus 5.5. No fallback model was used.

### Trigger and reachability

The trusted creator of a machine writes a configuration that sets `iflags.Y = 1` and `htif.tohost` to a manual yield with the rx-rejected reason. The manual documents both registers as configurable ("Each register field is a number that sets its value"), and the reason value is one it specifies.

No input sequence from any valid template produces a rejected yield whose revert root hash is not the content hash of the state the input was delivered to:

- A valid template waits at a manual yield with the accepted reason.
- The guest cannot run until a delivery clears `iflags_Y`. Only a delivery that changes the state does that (R5).
- That delivery writes the revert root hash with the referee-supplied before-hash (A4, R6). The emulator checks that this hash equals the current root hash, and no state's content hash is 0x00..00 without a break of the hash primitive.
- The guest cannot write the revert root hash (R8).

So the state is demonstrably unreachable. The defect is that creation lets a trusted configuration start there, which R4's configuration clause forbids.

### Rating

1. Out of scope: no.
   - Not "The effect of a deliberate state change made through the machine API, when the API performs it as documented". The settled reading applies: "Do not let the general 'deliberate state change ... performed as documented' exclusion excuse accepting a configuration the clause says must be rejected."
   - R4's exemptions are the full list, and this configuration meets all of them. It is reproducible, uses Keccak-256, and holds "only register values that the RISC-V specification and the manual allow".
   - The snapshot exclusions do not apply, because this is creation, not loading.
   - No application is involved.
2. Role: machine creation is "Honest operator where a production validator node plausibly calls it on the honest operator's path" (AUDIT.md row 2). The collectors and the uarch reset are Honest operator (row 1). Section 3: the honest operator role covers "the transition function, its log producers, the computation-hash builders".
3. High and Medium cases: "A divergence between paths only at demonstrably unreachable states." The mcycle-level builder commits to 0x00..00 at every later boundary. The uarch path run on the machine starts each later mcycle at the rejecting machine's root hash. The uarch-level builder cannot produce that mcycle's trajectory without a fabricated tail. This happens at a state no valid template reaches (argument above). High. The match is not literal: every collector agrees on 0x00..00, and the failure is the absence of any state behind that hash. This mirrors the confirmed R1-R4-1.
4. Critical: not reached under the preferred reading. Under the alternative reading, step 3 does not fit literally. Accepting the configuration then violates R4 at creation, an operation on the honest operator's path ("Obtaining its valid template"). The clause is "Every reproducible configuration that the emulator accepts, using the deployment's hash function and holding only register values that the RISC-V specification and the manual allow, yields a machine on which this rule holds. A configuration that would not is rejected when the machine is created." Section 8 makes that Critical: "violating any rule or obligation at a reachable state, or anywhere on the honest operator's path, is critical".

Readings:

- High (preferred).
- Critical, if the creation-time acceptance is itself an R4 violation on the honest operator's path that no High case absorbs.
- Low, if step 4 is read to need a reachable state or an honest-path operation, and creating a machine at a rejected yield is held to be off that path. Such a machine is not a valid template and can never become one by running or delivering inputs.

The deciding facts:

- whether R4's configuration clause binds every creation, as readings.md settles, or only creations that can lead to a valid template;
- whether a completeness failure confined to a machine created in an unreachable state counts as the High "divergence between paths" case.

### Possible solution and risks

At creation of a reproducible machine, reject a configuration whose registers put it at a manual yield with the rx-rejected reason. `is_rejected_manual_yield` is true at creation, and no configuration field can supply a matching revert root hash. A narrower check would reject a rejected yield whose revert root hash is zero. An alternative is to make the rejection exception refuse, rather than substitute, a revert root hash of zero. Risk: tests or tools that create machines directly at a rejected yield would need another setup, such as reaching the yield by running a guest. The check is one predicate at creation.

### Risk of not fixing it

Only the trusted creator of a machine can trigger it. A deployment template must wait at an accepted yield, and a machine created at a rejected yield can never become one, because its deliveries are no-ops. So no deployed template is exposed. The machine and its hashes look normal at the mcycle level until a dispute needs uarch-level claims or step proofs after the first boundary. At that point the honest operator cannot produce them. Mitigation outside the code: check that every template waits at a manual yield with the accepted reason before committing its hash, as `cartesi-machine --assert-rolling-template` does.
