# R2-DFYIELD-1: the PRT player's claim pass copies and hashes the guest-declared tx-buffer payload at every automatic yield

Component: PRT player, `doc/recipes/prt.lua` (`run_next_input` -> `run_to_input_mcycle_offset`, whose
`on_yield_automatic` closure is always defined there, -> `run_to_stop`, which calls `receive_cmio_request(machine)`
at every automatic yield). `machine:receive_cmio_request()` returns `min(tohost DATA, 2 MiB)` bytes of the tx
buffer, where DATA is the length the guest declares; for `TX_OUTPUT` the player then keccak-hashes those bytes. For
`TX_REPORT` it reads them and throws them away. Role (AUDIT.md): Support, an implementation of an operator that
computes claims, which stands in for the honest operator.

## Requirement

THREAT_MODEL.md section 8, High: "A defect that lets the guest, or host load that the deployment was sized for,
multiply the worst-case cost of an operation listed in R12 by a constant factor, compared with the same operation
without the defect, while staying within what the deployment was sized for. A cost that the specified semantics
require is not a defect." R12 lists "a part of a claim". Section 4: "The outputs Merkle root, the output payloads,
and every other yield reason are opaque guest data that the state merely commits to." A support component is capped
at Medium (section 3). Whether the outputs/yields exclusion of section 8 ("each yield costs it a bounded amount")
applies is for the reviewer to decide. This test only shows the behavior.

## What the test does

* Builds `guest.c` with `bugs/harness/baremetal/build.sh` into a temporary directory and stores a
  valid-template-style machine: first manual yield, rx-accepted, empty outputs root, both yield kinds enabled.
* For each input, the guest makes K = 50 automatic yields with the reason and declared length the input selects. It
  writes only an 8-byte counter to the tx buffer, spins to a fixed mcycle budget, and accepts with the outputs root
  the host computed. Before the player runs, a plain local machine without the player confirms this: 50 automatic
  yields with that reason and DATA, then an accepted manual yield.
* A fresh forked honest player (`prt.new_forked_player`, which the `honest` role of `prt.lua` runs) processes the
  input through `event_handler.input_added`, which calls `run_next_input`, the pass that builds its mcycle
  computation hash. The test wraps the machine method `receive_cmio_request` (local and JSON-RPC machines share one
  metatable) and `cartesi.keccak256` (wrapped before `prt` is loaded, since `prt` captures it then). The wrappers
  count the payload bytes this pass copies out of the machine and hashes.
* There are three inputs with the same yields and the same mcycles (8375): `control` (TX_OUTPUT declaring 8 bytes),
  `outputs` (TX_OUTPUT declaring 2 MiB) and `reports` (TX_REPORT declaring 2 MiB).
* The test asserts that for `outputs` and `reports`, the payload bytes copied plus hashed exceed the control by at
  most 1024 bytes per yield. Wall-clock times are printed for information only.
* Setup checks (exit 2 otherwise): the guest behaves as above without the player, the player's run ends at the
  accepted yield, and all inputs run the same mcycles. The player's output count and anomalies are only printed,
  since a fixed player may track outputs outside the claim pass.

The fix direction was checked with a scratch copy of `prt.lua` (not tracked) in which `run_to_stop` never reads
automatic-yield payloads. With it, the test exits 0: 0 extra bytes per yield, and every case takes about the same
time. That copy loses output tracking, so it is only a check of the assertion, not a proposed fix.

Environment knob: `R2_DFYIELD_1_YIELDS` (default 50).

## Run

```sh
bugs/run.sh R2-DFYIELD-1        # about 10 s
```

## Expected output on audit/prt2

```
control  yields=50 declared=8        mcycles=8375 ... receive: 51 calls 432 B | keccak: 361 calls 20304 B | time 0.03 s
outputs  yields=50 declared=2097152  mcycles=8375 ... receive: 51 calls 104857632 B | keccak: 361 calls 104877504 B | time 2.8 s
reports  yields=50 declared=2097152  mcycles=8375 ... receive: 51 calls 104857632 B | keccak: 138 calls 8832 B | time 2.4 s
outputs: ... 4194288 extra bytes per yield (allowed 1024); time ~80-100x the control
reports: ... 2096915 extra bytes per yield (allowed 1024); time ~70-80x the control
VIOLATED: section 8 High / R12 'a part of a claim': ...
run.sh: R2-DFYIELD-1: exit 1 (bug present)
```

The player's per-yield work is set by a length the guest declares without writing the bytes. Each yield costs the
guest a few mcycles (8375 mcycles for 50 yields plus the spin). The player copies 2 MiB over JSON-RPC at every
yield, and hashes 2 MiB more for outputs. The emulator's collector does not read payloads at all.
