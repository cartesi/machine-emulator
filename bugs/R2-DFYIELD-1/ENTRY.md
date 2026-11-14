## R2-DFYIELD-1

**Title.** The PRT player's claim pass copies, and for outputs keccak-hashes, the tx-buffer payload length that each automatic yield declares (up to 2 MiB), multiplying its per-yield cost by a guest-chosen length.

**Severity.** Medium (support component standing in for the honest operator, where it would rate High). Out of scope under a broad reading of the outputs/yields exclusion of section 8; see Rating.

### Problem

While the PRT player computes its mcycle-level claim for an epoch, `run_next_input` calls
`run_to_input_mcycle_offset` with a `last_output` table, which defines an `on_yield_automatic` callback. `run_to_stop`
then calls `receive_cmio_request(machine)` at every automatic yield. `machine:receive_cmio_request()` returns
`min(htif_tohost_data, 2 MiB)` bytes of the tx buffer. DATA is a length the guest declares in `tohost`, and the guest
does not have to write those bytes. For `TX_OUTPUT` the callback then keccak-hashes the payload. For `TX_REPORT` and
any other reason it reads the payload and drops it.

So one guest store to `tohost` (a few mcycles) makes the player copy up to 2 MiB, over JSON-RPC for a forked player,
and hash up to 2 MiB more. The emulator's own claim work for the same mcycles (`collect_mcycle_root_hashes`) reads no
payload at all. The computation hash depends only on state hashes. Section 4 says "The outputs Merkle root, the output
payloads, and every other yield reason are opaque guest data that the state merely commits to", and section 8 says
"Keeping outputs to prove them later is not on the honest operator's path". So the claim's semantics do not require
this work. Any guest, after it reads an input, can multiply the host cost of each automatic yield in the claim pass by
a large constant. Measured here: about 75-100x the time of an otherwise identical input, at the same mcycle count.
The hunter measured 170x locally and 470x over JSON-RPC for a tight yield loop.

This does not break the goal of section 1 by itself, because the factor is bounded. It removes the cost margin that
A7 sizes the clocks for (R12 "a part of a claim"), which is the High constant-factor case of section 8. The player is
a support component, so it is capped at Medium.

### Component, role and area

The PRT player in `doc/recipes` (`prt.lua`), the input pass that builds its mcycle computation hash. AUDIT.md
component table: "The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI, ... | Support. No production
deployment runs the player, the bridge or the CLI." The player is "an implementation of an operator" that "computes
claims" (THREAT_MODEL.md section 3), so it stands in for the honest operator. The `cartesi-machine` CLI's `run_to_stop`
(`src/cartesi-machine.lua`, which calls `get_and_print_yield` at every automatic yield) follows the same pattern and
is also Support. It is not tested here.

### Location

- `doc/recipes/prt.lua`: `receive_cmio_request` (about line 972), `run_to_stop` (about lines 1396-1410),
  `player_meta.__index:run_to_input_mcycle_offset` (about lines 2066-2124; the callback at 2081-2091 runs
  `keccak(output_data)` for `TX_OUTPUT`), `player_meta.__index:run_next_input` (about lines 2243-2272, the only
  caller that passes `last_output`, so the only one that enables the callback).
- `src/clua-i-machine.cpp` `machine_obj_index_receive_cmio_request` and `src/machine.cpp`
  `machine::receive_cmio_request`: these return the declared length of tx-buffer bytes. They work as documented; the
  defect is in how the caller uses them.
- The dispute replays (`run_to_epoch_input_offset`, `build_uarch_cycle_computation_hash` and others) pass no
  `last_output` and are not affected.

### Evidence and test

`bugs/R2-DFYIELD-1/` contains:

- `guest.c`, a bare-metal rollup guest built with `bugs/harness/baremetal/build.sh`. It boots by accepting with the
  empty outputs root. For each advance input it makes `count` automatic yields with the reason and declared length the
  input selects, writing only an 8-byte counter to the tx buffer. It then spins to a fixed mcycle budget and accepts
  with the outputs root the host passes in.
- `test.lua`. It stores a valid-template-style machine and checks the guest on a plain machine without the player.
  Then, for each of three inputs (the same 50 yields and 8375 mcycles each), it runs a fresh forked honest player
  (`prt.new_forked_player`) through `event_handler.input_added`, which calls `run_next_input`. It wraps the machine's
  `receive_cmio_request` method and `cartesi.keccak256` to count the payload bytes the pass copies and hashes. The
  inputs are `control` (TX_OUTPUT declaring 8 bytes), `outputs` (TX_OUTPUT declaring 2 MiB) and `reports` (TX_REPORT
  declaring 2 MiB). The test asserts that the per-yield excess over the control is at most 1024 bytes. It exits 2 on
  setup errors: the guest does not behave, an input is not accepted, or the mcycle counts differ.
- `README.md`, the prover's description.

Run: `bugs/run.sh R2-DFYIELD-1` (about 10 s). It exited 1 on both of the reviewer's runs, with identical byte
counts each time. It prints:

```
control  yields=50 declared=8        mcycles=8375   accepted=true outputs=50  receive: 51 calls 432 B | keccak: 361 calls 20304 B | time 0.030 s | anomalies={}
outputs  yields=50 declared=2097152  mcycles=8375   accepted=true outputs=50  receive: 51 calls 104857632 B | keccak: 361 calls 104877504 B | time 2.949 s | anomalies={}
reports  yields=50 declared=2097152  mcycles=8375   accepted=true outputs=0   receive: 51 calls 104857632 B | keccak: 138 calls 8832 B | time 2.968 s | anomalies={}
outputs: payload bytes copied+hashed by the claim pass 209735136 vs control 20736: 4194288 extra bytes per yield (allowed 1024); time 97.96x the control
reports: payload bytes copied+hashed by the claim pass 104866464 vs control 20736: 2096915 extra bytes per yield (allowed 1024); time 98.60x the control
VIOLATED: section 8 High / R12 'a part of a claim': ...
run.sh: R2-DFYIELD-1: exit 1 (bug present)
```

Timings vary between runs (74-98x on the second run); the byte counts do not, and only the byte counts are asserted.
The player reports no anomaly and the outputs root matches, so the guest is a correctly designed application. The
`reports` case alone isolates the defect: its payload is read on the claim path and thrown away. The prover reports
that a scratch `prt.lua` whose `run_to_stop` does not read automatic-yield payloads makes the test exit 0. Found,
proved and reviewed by Opus 5.5; no fallback model was used.

### Trigger and reachability

Any guest code after it reads an input (section 4, "guest code after it reads an input" is untrusted) can trigger
this. Each automatic yield is one store of `yield | automatic | reason | DATA` to `tohost`, with DATA up to the 2 MiB
tx-buffer length, and costs the guest a few mcycles. Section 2 says "Any assignment of guest-writable memory and
registers is presumed reachable", and the test reaches the state from a stored template through ordinary input
delivery. No unreachability argument is needed. Automatic yields are enabled in the default configuration, and every
honest player runs `run_next_input` on every input.

### Rating

1. Out of scope. The exclusion that comes closest is "An application that tries to exhaust the honest operator
   through the number of its outputs or yields. Each costs the guest mcycles, which the application's own bound limits
   (section 2). This holds as long as ... each yield costs it a bounded amount (R12)." The preferred reading is that it
   does not cover this defect. The trigger is not the number of yields: the test keeps the yields (50) and the mcycles
   (8375) fixed and changes only the declared length, and the cost grows 75-100x. "How to rate" says "Check the
   trigger, not the symptom" and that the application entries "exclude what an application loses, never an emulator
   defect that its guest triggers". The clause's proviso, "a bounded amount (R12)", points at R12, and section 8 rates
   a defect that multiplies an R12 cost by a constant factor as High even though the cost stays bounded. The guest is
   correctly designed, so the "not correctly designed" exclusion does not apply either, and in any case it never
   excuses the honest operator's claim work (R4). Under the broad reading, where any per-yield cost with a constant
   upper bound (2 MiB) satisfies "bounded amount", the finding is Out of scope.
2. Role. The defect is in the PRT player, a component in the Support role per AUDIT.md: "The PRT player and bridge in
   `doc/recipes` ... | Support". Section 3: "A defect that only a support component shows is Medium when it would rate
   High or Critical in the role the component stands in for, such as ... the honest operator for an implementation of
   an operator or a tool that computes claims." This clause covers the player, which computes claims. No component in
   the honest-operator role shares the defect: `collect_mcycle_root_hashes` and the machine API read no payload unless
   asked.
3. High and Medium cases. In the honest-operator role the defect matches section 8 High: "A defect that lets the guest
   ... multiply the worst-case cost of an operation listed in R12 by a constant factor, compared with the same
   operation without the defect, while staying within what the deployment was sized for. A cost that the specified
   semantics require is not a defect. When the sizing is unknown, rate such a constant-factor increase High". R12 lists
   "a part of a claim". The claim's semantics do not require payload reads: section 4 calls output payloads and other
   yield reasons "opaque guest data that the state merely commits to", and section 8 says "Keeping outputs to prove
   them later is not on the honest operator's path". If the factor exceeded the deployment's sizing it would be
   Critical in that role. Either way, the support cap gives the Medium case "A defect that only a support component
   shows, when section 3 rates it Medium."
4. Critical. Not reached. The support cap in step 2 ("never above Medium") applies.

Two readings: Medium under the narrow reading of the outputs/yields exclusion (preferred), and Out of scope under the
broad one. The deciding question is whether "each yield costs it a bounded amount (R12)" is met by any constant upper
bound per yield, or only by a per-yield cost that no defect has multiplied, as the High constant-factor clause
requires. The threat model does not say. A second, smaller question is whether output hashing inside the claim pass
counts as a cost that "the specified semantics require". The threat model puts keeping outputs off the honest
operator's path, so this review says no. The `reports` half of the test does not depend on that question.

### Possible solution and risks

In `run_to_stop` or the callback, read only the reason (`htif_tohost_reason`) at an automatic yield, and never copy
the payload of a non-output yield. Move output tracking (reading and hashing `TX_OUTPUT` payloads to build the
outputs frontier and the last-output proof) out of the claim pass. For example, do it in a separate pass or machine
that does not delay the claim, or only when output proofs are wanted. The automatic-yield callback should be limited
to that pass. Risks: the player's output proofs and the outputs-root anomaly check depend on the frontier built in
this pass, so moving it must keep `commit_epoch_state`, the stored `outputs_frontier` and `last_output`, and
`prove_outputs_merkle_root` consistent across restarts (O2). A narrower fix that only stops reading report payloads
removes the `reports` half and still hashes up to 2 MiB per output in the claim pass, so the test keeps exiting 1 for
`outputs`. The CLI's `run_to_stop` could get the same treatment, but as a development tool it may keep printing
payloads.

### Risk of not fixing it

No production deployment runs the player, so a real deployment is not exposed. The risk is to anyone who uses the
player, or copies its loop into a validator node, as a model of an honest operator. Such a node takes about 2-5 ms
(local) or tens of ms (JSON-RPC) per automatic yield on the claim path instead of tens of microseconds. Any input
sender whose input reaches guest code that loops on automatic yields can impose this, within the application's
mcycle bound. That can push claim computation for an epoch, and processing of later epochs, past clocks sized for the
emulator's own costs. Mitigations outside the code: disable automatic yields where outputs are not needed, or size
the clocks for 2 MiB of copying and hashing per few mcycles.
