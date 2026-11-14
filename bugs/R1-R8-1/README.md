# R1-R8-1: the PRT player's claim-computing run holds one hash per guest output

Component: PRT player, `doc/recipes/prt.lua` (`player_meta.__index:run_to_input_mcycle_offset`, its
`on_yield_automatic` closure and `pending_output_hashes`, folded into the outputs frontier only by
`flush_pending_outputs` at an accepted manual yield). Role (AUDIT.md): Support, an implementation of an operator.

## Requirement

THREAT_MODEL.md, R12: "The memory and storage the honest operator needs to defend its claims do not grow with the
number of outputs." Section 8 (Out of scope) excludes applications that exhaust the operator through their outputs
only "as long as the memory and storage that the honest operator needs to defend its claims do not grow with the
number of outputs".

## What the test does

* Builds `guest.c` with `bugs/harness/baremetal/build.sh` into a temporary directory (a few seconds, docker
  toolchain image) and stores a valid-template-style machine (first manual yield, rx-accepted, empty outputs root).
* Each input tells the guest how many outputs to emit (automatic TX_OUTPUT yields; output i is the 8-byte counter i),
  how many mcycles to spend in total (it spins after the outputs), and the outputs root to accept with (computed by
  the host, so the player reports no root mismatch).
* For each case, a fresh forked honest player (`prt.new_forked_player`, as `crisium.lua` runs it) processes one
  input through its normal `input_added` handler, i.e. the epoch run that builds its mcycle computation hash. A Lua
  count hook samples the live Lua heap (after a full collection) during the run.
* Control: 1000 outputs; test: 100000 outputs; both inputs run exactly the same mcycles (3,200,186), so only the
  number of outputs differs. Setup checks (exit 2 otherwise): both accepted, `player.output_count` equals the
  emitted count, no `outputs_merkle_root_mismatch`, equal mcycles.
* Asserts: peak live heap (test) minus peak live heap (control) < 1 MiB. Checked against a scratch copy of
  `prt.lua` that updates a copy of the outputs frontier on each output (discarded on reject; the frontier before
  the last push kept for its proof) instead of the list of hashes: the difference is then -28 KiB, the roots still
  match, and the test exits 0.
* Informational only, not asserted: the number of `oversized_output` anomalies for an input with 1 and with 4
  outputs that declare a length larger than the tx buffer (one anomaly per output today). Anomaly logs are not
  memory "needed to defend its claims" and R12 allows a bounded cost per yield, so this is reported, not tested.

Environment knobs: `R1_R8_1_SMALL` (default 1000), `R1_R8_1_LARGE` (default 100000).

## Run

```sh
bugs/run.sh R1-R8-1        # about 75 s
```

## Expected output on audit/prt2

```
control   outputs=1000    declared_len=8  mcycles=3200186 accepted=true player.output_count=1000   ... extra_peak_heap=161 KiB anomalies={}
large     outputs=100000  declared_len=8  mcycles=3200186 accepted=true player.output_count=100000 ... extra_peak_heap=8659 KiB anomalies={}
over-1    outputs=1       declared_len=2097153 ... anomalies={oversized_output=1}
over-4    outputs=4       declared_len=2097153 ... anomalies={oversized_output=4}
info: oversized_output anomalies per input: 1 (1 output), 4 (4 outputs)
peak live heap growth from 1000 to 100000 outputs at equal mcycles: 8497 KiB (87.9 bytes/output)
VIOLATED: R12: the memory the honest operator needs to compute its claim must not grow with the number of outputs (...)
run.sh: R1-R8-1: exit 1 (bug present)
```

Exit 1 = bug present, 0 = fixed, 2 = setup error (for example a full disk while building the guest or storing the
template).
