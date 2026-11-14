## R1-R8-2

**Title.** The honest player in `vg.lua` stops computing its claim when an accepted input leaves an outputs root that does not match its outputs.

**Severity.** Medium. Under a second reading, where `vg.lua`'s player counts as a development tool, it is Out of scope.

### Problem

When an input is accepted, `flush_pending_outputs` in `doc/recipes/vg.lua` hashes the outputs the input emitted into
the outputs frontier. It then runs
`assert(hash_tree.frontier_get_root_hash(outputs_frontier) == outputs_merkle_root, "outputs Merkle root mismatch")`.
The tx-buffer root is opaque guest data. Section 4 says: "The outputs Merkle root, the output payloads, and every
other yield reason are opaque guest data that the state merely commits to." The guest controls that root. If the root
it leaves does not match its outputs, `event_handler:input_added` raises. Then `state_hashes_before_inputs` and
`input_mcycle_lengths` are not recorded for the input, and `epoch_sealed` and `commit_claim` cannot produce the final
state hash. The state transition function still defines that final state and its hash. The player that stands in for
the honest operator therefore stops computing its claim. In the operator this player models, that lets any claim win,
including a fabricated final state and its outputs (section 8). The PRT player in the same directory handles the same
condition correctly: `prt.lua` reports an `outputs_merkle_root_mismatch` anomaly and continues.

### Component, role and area

The component is the honest player of the verification-game recipe, `doc/recipes/vg.lua` (`vg.new_player`,
`event_handler`). It is not listed by name in the AUDIT.md table, but it falls under the row "The PRT player and bridge
in `doc/recipes`, the `cartesi-machine` CLI, and the Lua helper libraries ... | Support. No production deployment runs
the player, the bridge or the CLI". It also fits section 3's "Support. Everything else used only for tests,
demonstrations, development or diagnostics". The player is an implementation of an operator that computes claims, so
it stands in for the honest operator. The area is how outputs are tracked while inputs are processed.

### Location

- `doc/recipes/vg.lua`: `flush_pending_outputs` (lines 421-430, the assert at line 429).
- `player_methods:run_to_input_mcycle_offset` (lines 434-480, which calls it at line 474).
- `event_handler:input_added` (lines 563-577), from which the error escapes.

### Evidence and test

`bugs/R1-R8-2/` contains the following files.

- `guest.c` is a bare-metal guest. It is built at test time with `bugs/harness/baremetal/build.sh` and handles inputs
  as follows:
  - At start, it accepts with the empty outputs root.
  - On input `W`, it emits nothing and accepts with a root that is not the root of its outputs (every byte XOR 0x5a).
  - On input `O`+N, it emits N outputs of 2 MiB and accepts with the correct root.
- `test.lua` stores the initial machine under its hash. It then drives `vg.new_player(initial_hash, "honest")` the way
  the referee's runner does, through `event_handler.input_added`, `epoch_sealed` and `commit_claim`.
  - Check A asserts two things: `input_added` for input `W` returns, and the committed claim equals the root hash after
    that input, computed independently with the Lua API.
  - Check B measures how much the player's Lua heap grows for 1 and for 16 outputs of 2 MiB. It is printed only, not
    asserted (see below).
- `README.md` describes the test.

Run it with `bugs/run.sh R1-R8-2`. It takes a few seconds and needs docker for the guest build. On audit/prt2 it
prints:

```
check A: input_added raised: /home/user/machine-emulator/doc/recipes/vg.lua:429: outputs Merkle root mismatch; claim none; reference 0xb40f71eb6f11e3ecd48da7b04c5fabe0958e62f9146c3f8bc9b1a698f8def78d
check B: heap growth across input_added: 1 outputs -> 2.00 MiB, 16 outputs -> 32.00 MiB (difference 30.00 MiB; one output is 2.00 MiB)
VIOLATED: R4/section 8: an accepted input whose outputs root does not match its outputs must not stop the honest player from computing its claim
note (not asserted): the honest player's Lua heap grows with the number of outputs it keeps for prove_output; section 8 puts keeping outputs to prove them later off the honest operator's path
run.sh: R1-R8-2: exit 1 (bug present)
```

The result was the same (exit 1) in every run. The reviewer repaired the test:

- **Before the repair.** The prover's version also failed the test when check B failed.
- **Why check B no longer decides the result.** The payloads are kept for `prove_output`, and section 8 says "Keeping
  outputs to prove them later is not on the honest operator's path". A correct fix of the stop alone would therefore
  still have failed the test.
- **After the repair.** A copy of `vg.lua` in which the assert at line 429 only writes a warning (put first on
  `LUA_PATH_5_4`) makes the test print `check A: input_added returned; claim 0xb40f...f78d; reference 0xb40f...f78d`
  and exit 0.

The candidate was found, proved and reviewed on `claude-opus-5-5`, with no fallback.

### Trigger and reachability

Any guest that accepts an input while leaving in the tx buffer a root other than the root of its outputs triggers the
stop. Three kinds of guest do this:

- An application that breaks the rollup interface.
- A buggy application.
- A correctly designed application that an input has taken over. Section 4 says: "Any input may take control of the
  firmware, the kernel, the rollup libraries, and the application."

The tx buffer is guest-writable, and section 2 says: "Any assignment of guest-writable memory and registers is
presumed reachable." The state is therefore reachable from any valid template. The input sender needs only one
accepted input.

### Rating

1. **Out of scope.** The following exclusions were checked:
   - *Applications that are not correctly designed.* This exclusion does not cover the defect. It covers "only what
     such an application gets, which is its outputs and its own correctness", and it adds: "An application that breaks
     the rollup interface may leave its outputs unprovable, but it must never stop the honest operator from computing
     claims or producing proofs. Development tools may instead stop and report the violation." That last permission
     covers this player only if the player is a development tool. Section 3 lists "implementations of an operator that
     no deployment runs" and "development tools" as separate examples, and the manual presents `vg.lua`'s honest player
     as the player that defends an epoch. So the best-supported reading is that it is an operator implementation, not a
     development tool, and the defect is in scope.
   - *Stalls of an application that halts or yields with another reason.* This does not apply, because the guest
     accepts.
   - *Exhausting the operator through outputs.* This exclusion ("Keeping outputs to prove them later is not on the
     honest operator's path") applies to the memory growth of check B, which is therefore not part of this finding.
2. **Role.** The component is Support. Section 3 says: "A defect that only a support component shows is Medium when it
   would rate High or Critical in the role the component stands in for, such as ... the honest operator for an
   implementation of an operator or a tool that computes claims." This clause covers `vg.lua`'s honest player, which
   computes and commits claims. Only this support component shows the defect: `prt.lua` reports
   `outputs_merkle_root_mismatch` as an anomaly instead.
3. **High and Medium cases.** Two cases were checked:
   - In the stood-in honest-operator role, no listed High or Medium case fits. The trigger is a guest state, not data
     the operator may decline, and not an unreachable state.
   - As a support defect, it matches the Medium case "A defect that only a support component shows, when section 3
     rates it Medium".
4. **Critical (in the stood-in role).** The defect would be Critical in the honest-operator role. R4 says: "From any
   reachable state ... the honest operator can always compute the claim ... This holds for every guest, whether or not
   its application is correctly designed (section 8)." The defect breaks this at a reachable state. Section 3 caps it at
   Medium for Support.

Two readings give different classes:

- **Best-supported reading: Medium.** The player is an implementation of an operator that stands in for the honest
  operator.
- **Second reading: Out of scope.** The player is a development tool, which may "stop and report the violation". The
  raised error does report the violation.

What decides between them is whether section 3's "a tool that computes claims" counts as a section 8 "development
tool". The manual's description of `vg.lua` as the player of the verification game, and its distinct listing from
development tools in section 3, favour the first reading.

### Possible solution and risks

In `flush_pending_outputs`, replace the assert with a report and continue. For example, log the mismatch, or record a
flag that disables output proofs for the epoch, as `prt.lua` does with `report_anomaly`. Then `input_added` records the
input's hash and length whatever the root holds.

The main risk is in `epoch_sealed` and `prove_output`. They would then build proofs from a frontier whose root differs
from the root extracted from the settled state, and the referee would reject those proofs. That is harmless, but
`prove_output` should not offer them, and should answer "nothing" when the roots disagree. Separately, the player could
keep only output hashes plus the last payload, as `prt.lua` does, to bound its memory. That is a hardening step, not
part of this fix.

### Risk of not fixing it

`vg.lua` is a recipe that no deployment runs, so no funds are exposed. Anyone who builds an operator from this
manual-documented recipe inherits a player that any input sender can stop, by taking over the application or by
targeting a misbehaving one, with a single accepted input. In a real deployment, that would let a dishonest claim
settle unopposed. As a mitigation outside the code, the manual could state that the honest player must tolerate a
mismatched outputs root, and point to `prt.lua`'s behaviour.
