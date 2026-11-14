## R1-R8-1

**Title.** The PRT player keeps one hash per guest output for a whole input, in the same run that computes its claim, so the memory it needs to compute the claim grows with the number of outputs.

**Severity.** Medium

### Problem

While the PRT player runs an input, `run_to_input_mcycle_offset` installs an `on_yield_automatic` closure. For every
automatic yield with the TX_OUTPUT reason, the closure appends `keccak(output_data)` to the Lua table
`pending_output_hashes`. The table is folded into the outputs frontier only at the input's fixed point, by
`flush_pending_outputs`, when the input is accepted. On any other outcome it is dropped when the function returns. The
player does this in the epoch run that also feeds the mcycle computation-hash builder (`run_next_input`, called from
`input_added` and `idle`). That run is how the player computes its claim. Within one input, the run therefore holds
about 88 bytes of Lua heap per output: a 32-byte string plus its table slot.

Each output costs the guest only a few mcycles (a store to the tx buffer and an automatic yield). The mcycle limit per
input is 2^48 (`cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE` = 48). So a single input can make the claim
computation's memory grow, in principle up to tens of bytes per mcycle the guest runs. That is far beyond the machine's
own fixed memory. A host that runs out of memory stops the claim computation. In the role the player stands in for,
that is the completeness failure of section 1: the honest operator "cannot respond in time. If the honest claim is
eliminated, a dishonest claim can win". The threat model rules this out explicitly. R12: "The memory and storage the
honest operator needs to defend its claims do not grow with the number of outputs."

Nothing in the claim needs these hashes. The claim depends only on state hashes. The hashes serve only to check the
outputs root and to prove the input's last output, which the frontier could do in constant memory (63 hashes).

The secondary observation in the triage item, one `oversized_output` anomaly line per oversized output, is not part of
this entry. R12 allows a bounded cost per yield, and the test only reports it.

### Component, role and area

The PRT player in `doc/recipes` (`prt.lua`, run by `crisium.lua` and by the forked players), in its epoch execution and
output bookkeeping. AUDIT.md table: "The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI, ... |
Support. No production deployment runs the player, the bridge or the CLI." It is an implementation of an operator that
computes claims, so it stands in for the honest operator (section 3).

### Location

`doc/recipes/prt.lua`:

- `player_meta.__index:run_to_input_mcycle_offset`, lines 2066-2126. Line 2080 creates `pending_output_hashes`. The
  `on_yield_automatic` closure (2083-2091) appends one hash per TX_OUTPUT yield at line 2088.
- `flush_pending_outputs`, lines 1419-1437, which folds the list into the frontier only at acceptance.
- `player_meta.__index:run_next_input`, lines 2243-2272, the claim-building epoch run that passes `last_output` and
  `self.outputs_frontier`, which enables the closure.

### Evidence and test

`bugs/R1-R8-1/` contains:

- `test.lua`, the test.
- `guest.c`, a bare-metal rollup guest. Each input carries an output count, a declared length, an mcycle budget and the
  outputs root to accept with. The guest emits that many automatic TX_OUTPUT yields, where output i is the 8-byte
  counter i. It then spins to the mcycle budget and accepts with the root.
- `README.md`.

The test builds the guest with `bugs/harness/baremetal/build.sh` into a temporary directory. It stores a template at
the guest's first manual yield (rx-accepted, empty outputs root). For each case, a fresh `prt.new_forked_player` runs
one input through its normal `input_added` handler, which is the claim-building epoch run. A Lua count hook samples the
live Lua heap after a full collection during the run.

There are two cases. The control emits 1000 outputs and the test emits 100000. Both run exactly 3,200,186 mcycles. The
test exits 2 unless both inputs are accepted with no root mismatch, `player.output_count` equals the emitted count, and
the mcycles are equal. It asserts that the peak heap of the test minus that of the control is under 1 MiB.

Run `bugs/run.sh R1-R8-1` (about 80 s). It prints this on audit/prt2. The reviewer's run printed the same numbers as
the prover's.

```
control   outputs=1000    declared_len=8        mcycles=3200186  accepted=true player.output_count=1000    heap_samples=17   extra_peak_heap=161 KiB anomalies={}
large     outputs=100000  declared_len=8        mcycles=3200186  accepted=true player.output_count=100000  heap_samples=1666 extra_peak_heap=8659 KiB anomalies={}
over-1    outputs=1       declared_len=2097153  mcycles=3200186  accepted=true player.output_count=1       heap_samples=0    extra_peak_heap=0 KiB anomalies={oversized_output=1}
over-4    outputs=4       declared_len=2097153  mcycles=3200186  accepted=true player.output_count=4       heap_samples=0    extra_peak_heap=0 KiB anomalies={oversized_output=4}
info: oversized_output anomalies per input: 1 (1 output), 4 (4 outputs)
peak live heap growth from 1000 to 100000 outputs at equal mcycles: 8497 KiB (87.9 bytes/output)
VIOLATED: R12: the memory the honest operator needs to compute its claim must not grow with the number of outputs (peak heap difference 8497 KiB, margin 1024 KiB)
run.sh: R1-R8-1: exit 1 (bug present)
```

The reviewer also checked that the test passes once the defect is fixed, using a scratch copy of `prt.lua` that was
not committed. In that copy, the closure pushes each output's hash into a copy of the outputs frontier and holds back
only the last hash. At acceptance it proves the last hash against the copy, pushes it, and installs the copy. With it,
the roots still match (no `outputs_merkle_root_mismatch`), the growth is 7 KiB (0.1 bytes/output), and the test exits 0.
The test was not modified. Found, proved and reviewed on Opus 5.5 (no fallback).

### Trigger and reachability

An input sender triggers it. After the guest reads an input, it may run any instruction stream (section 4). That
includes a loop of automatic TX_OUTPUT yields, for example with zero- or eight-byte outputs, before it yields manually.
No special state is needed. Any valid template whose guest can be driven to emit outputs reaches it, including a
correctly designed application that emits many outputs for one input. Its memory cost is bounded per input only by the
mcycles the input runs (at most 2^48), and the table is released at the input's end.

### Rating

1. Out of scope: not excluded. The relevant exclusion reads: "An application that tries to exhaust the honest operator
   through the number of its outputs or yields. ... This holds as long as the memory and storage that the honest
   operator needs to defend its claims do not grow with the number of outputs, and each yield costs it a bounded amount
   (R12)." Here the claim-computing run's memory grows with the number of outputs, so the condition of the exclusion
   fails. The exclusion of applications that are not correctly designed "covers only what such an application gets",
   and "it must never stop the honest operator from computing claims", so it does not apply either. "Keeping outputs to
   prove them later is not on the honest operator's path" does not excuse it: the player does this keeping inside the
   run that computes the claim, so the cost lands on that path.
2. Role: the PRT player is Support (AUDIT.md table, quoted above). Section 3: "A defect that only a support component
   shows is Medium when it would rate High or Critical in the role the component stands in for, such as ... the honest
   operator for an implementation of an operator or a tool that computes claims." The player computes claims, so the
   defect is rated as if the honest operator had it, and then capped at Medium. No component in another role shares
   it. The emulator's own `collect_mcycle_root_hashes` and the frontier helpers keep no per-output list.
3. High and Medium cases, in the honest-operator role: none fits. The constant-factor case ("multiply the worst-case
   cost of an operation listed in R12 by a constant factor") does not fit, because the memory of a part of a claim goes
   from constant to linear in the output count, not up by a constant factor.
4. Critical, in the honest-operator role: R12, "The memory and storage the honest operator needs to defend its claims
   do not grow with the number of outputs", is violated at a reachable state, on the honest operator's path ("Computing
   claims", section 2). The Critical case "An operation listed in R12 whose worst-case cost a guest can make ... larger
   than what the deployment was sized for" also fits, since a guest controls the output count up to the per-input mcycle
   limit. Critical in the stood-in role makes it Medium for the support component.

Another reading gives Low. Under it, the hashes are memory for "keeping outputs to prove them later", which is "not on
the honest operator's path". Memory linear in the mcycles run is allowed by R12's first paragraph ("at most linear in
the cycles it executes"). So no rule is violated. What decides between the readings is whether "the memory ... the
honest operator needs to defend its claims" means the memory its claim-computing run actually consumes, or only what an
ideal operator strictly needs. The reviewer prefers the first reading. The exclusion in section 8 exists to stop
exhaustion through outputs, and a run that runs out of memory stops the claim whatever the memory was for.

### Possible solution and risks

In `run_to_input_mcycle_offset`, replace `pending_output_hashes` with a working copy of the outputs frontier
(`hash_tree.frontier_copy`), taken at input start. On each output, push the previously held hash into the copy and hold
only the newest hash and data. At acceptance, prove the held hash against the copy (`prove_next_output`), push it, and
install the copy as the player's outputs frontier (or swap the reference in `self.outputs_frontier`). On rejection or
at any other fixed point, drop the copy. Memory per input is then O(tree height). The reviewer's scratch version of
this passes the test with matching roots.

Risks: the frontier must be installed by reference or replaced in place, because `self.outputs_frontier` and
`previous_outputs_frontier` are compared for `output_count`. The last-output proof must still be taken before the last
push. The stored player persists the frontier and the last output, and its files and restart path must see the same
values as before. Pushing per output also costs about 63 hash operations per output in the worst case, compared with
the same total today, so it adds no asymptotic cost.

### Risk of not fixing it

No production deployment runs the player, so no deployment is directly exposed. Anyone who runs the recipe player,
`crisium.lua`, as a validator or sentinel for a real application is exposed. Any input sender can make one input's
claim computation exhaust the host's memory by having the guest emit many outputs. The player then cannot compute or
defend its claim. The player is also the reference that production operators may copy, and this per-output bookkeeping
would carry the same exhaustion into them. Mitigation outside the code: none practical, beyond provisioning memory for
the worst-case number of outputs an input can emit within its mcycle limit.
