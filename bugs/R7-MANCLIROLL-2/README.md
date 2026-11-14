# R7-MANCLIROLL-2: documented uarch computation-hash shortcut aborts after any earlier accepted output

## What is asserted

The manual (doc/README.md, "Computation hashes") says:

> The uarch cycle computation hash needs no epoch files. [...] A period in a later input does not require running
> the epoch from its start. Given a machine at the state that receives that input, `begin_epoch:false` with
> `next_input_offset` set to the input's zero-based offset in the epoch, counting rejected inputs, starts there.

The test checks that this documented command, run on the machine that receives input 1, exits 0 and prints the
same uarch cycle computation hash as the run from the template with `begin_epoch:true` over inputs 0..1.

Requirement: THREAT_MODEL R4, "From any reachable state, at the position where it is reached, the honest operator
can always compute the claim". It applies to the `cartesi-machine` CLI as "a tool that computes claims" (section 3,
Support). Section 8 adds: "A contradiction between the manual and the behavior on a security-relevant point ...
takes the severity it would have if the manual were right."

## Setup

- Guest: the harness `baremetal-template` (`emit-output.c`). It is a correctly designed application: each advance
  payload becomes one output and one report, and the guest accepts with the updated outputs Merkle root. Payload
  `R` makes it reject.
- Every CLI run uses the manual's server form (`--remote-spawn --remote-shutdown`, revert mode fork). Each server
  is shut down by the CLI itself. Period: `log2_mcycle_period:10`, `mcycle_period_index:2^38+100000`. That period
  is in input 1, in its padded tail after the input stops.
- Reference: from the template, inputs 0..1, `begin_epoch:true`.
- `--store` after input 0 gives the machine at the state that receives input 1. The test checks that it waits at an
  rx-accepted manual yield.
- control2 (setup check): input 0 is rejected, so no output is accepted before input 1. The documented shortcut
  must exit 0 and match its reference.
- control (setup check): input 0 is accepted with one output. The shortcut plus `check_outputs_merkle_root:false`
  must match the reference.
- target: the same machine and the documented shortcut with no epoch files. The test asserts exit 0 and the
  reference hash.

A failing control exits 2 (setup error).

## Run

```sh
bugs/run.sh R7-MANCLIROLL-2      # about 1 s
```

## Expected output on audit/prt2

```
control2 (input 0 rejected): reference 0x7a27bb69..., shortcut exit 0, hash 0x7a27bb69...
reference (from template, inputs 0..1, begin_epoch:true): 0xad98ec9470b66bb1d00bb11b1c4518d7a214e8e5d70e8ae8c76f7d60807a5710
control (shortcut + check_outputs_merkle_root:false): exit 0, hash 0xad98ec94...
target (documented shortcut after an accepted output): exit nonzero, hash nil
  CLI error: .../src/cartesi-machine.lua:3692: outputs Merkle root mismatch at input 1
VIOLATED: R4 / doc/README.md: ...
run.sh: R7-MANCLIROLL-2: exit 1 (bug present)
```

## Cause

With `begin_epoch:false` and no `outputs_frontier` or `last_output_proof`, `initialize_cmio_outputs` in
src/cartesi-machine.lua starts an empty host outputs frontier. The guest's tx-buffer root, however, commits to the
output accepted at input 0. At input 1's rx-accepted yield, `flush_pending_outputs` (check_outputs_merkle_root
defaults to true) raises the mismatch. This happens before `end_input` completes a period that lies after the
input's stop, so no claim is printed.

Facts for the reviewer:

- The help text of `check_outputs_merkle_root` says the host tree is initialized "from outputs_frontier or
  last_output_proof, or start empty at genesis". So a documented opt-out exists (pass `outputs_frontier` or
  `last_output_proof`, or `check_outputs_merkle_root:false`). The manual's shortcut paragraph mentions none of them.
- With the check disabled, the output file is named `output-0-input-1.bin`, not global index 1. The host index
  also starts at 0.
