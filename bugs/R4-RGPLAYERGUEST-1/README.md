# R4-RGPLAYERGUEST-1: the cartesi-machine CLI computes no mcycle computation hash for a guest that accepts with an outputs-root length other than 32

## What is asserted

`guest.c` is a bare-metal rollup guest that never emits outputs. It writes the root of the empty outputs tree to
the tx buffer and yields manual RX_ACCEPTED. The yield DATA (the length) is 32, unless the input's first byte is
`z` (DATA 0) or `Z` (DATA 0xffffffff). The test builds it with the harness bare-metal builder and stores the
template at its first rx-accepted yield. Then it runs two one-input epochs from that template:

| case | input | guest yield |
|---|---|---|
| control | `a` | RX_ACCEPTED, DATA 32 (a correctly designed guest) |
| target | `z` | RX_ACCEPTED, DATA 0, with the same correct root in the tx buffer |

For each case the test runs
`cartesi-machine --load=m,sharing:all --revert-mode=stored --cmio-advance-state=input:input-%i.bin,input_file_index_begin:0,input_file_index_end:1,check_outputs_merkle_root:false --mcycle-computation-hash=log2_mcycle_period:10,filename:hash.bin`.
It requires exit 0 and a `hash.bin` equal to the claim root that the PRT player (`prt.new_forked_player`,
`commit_mcycle_claim`) computes for the same template and input. The control case validates the comparison: the
CLI and the player agree there, and a mismatch would be a setup error (exit 2).

The target state is reachable: the yield DATA field is guest-writable (section 2, "Any assignment of
guest-writable memory and registers is presumed reachable"). The emulator does not interpret it (section 4: "The
outputs Merkle root, the output payloads, and every other yield reason are opaque guest data"). The state is an
accepted fixed point and its claim is well defined. The PRT player computes that claim.

`--uarch-cycle-computation-hash=...,mcycle_period_index:0` is also run and reported, but it is not asserted. In
the target case the CLI writes that hash and only then aborts with exit 1. The hash it writes equals the one a
fixed CLI produces.

## Requirement

- THREAT_MODEL R4: "From any reachable state, at the position where it is reached, the honest operator can always
  compute the claim ... This holds for every guest, whether or not its application is correctly designed".
- Section 8: "An application that breaks the rollup interface may leave its outputs unprovable, but it must never
  stop the honest operator from computing claims or producing proofs. Development tools may instead stop and
  report the violation."
- Section 3 (Support): "the honest operator for an implementation of an operator or a tool that computes claims".

The defect is at `src/cartesi-machine.lua` `flush_pending_outputs`:
`assert(#data == cartesi.HASH_SIZE, "expected outputs Merkle root in tx buffer")`. It runs on every rx-accepted
yield before `builder:end_input`, whatever builder is selected. `check_outputs_merkle_root:false` turns off only the
root comparison that follows, not this assert. With the default `check_outputs_merkle_root:true`, a root that
differs from the host's outputs tree aborts the run the same way. The test does not exercise that case, because an
option disables it.

## Run

```sh
bugs/run.sh R4-RGPLAYERGUEST-1      # about 12 s; needs docker (toolchain image) for the guest build
```

## Expected output on audit/prt2

```
target (input "z", guest accepts with DATA 0):
  PRT player claim root:          0x90b54dcb...273ec4
  CLI --mcycle-computation-hash:  FAILED, no hash written
    lua5.4: .../src/cartesi-machine.lua:3689: expected outputs Merkle root in tx buffer
VIOLATED: R4 / section 8: ...
run.sh: R4-RGPLAYERGUEST-1: exit 1 (bug present)
```

The control case passes: the CLI and the player both give 0xd40f8518...a07de1. A copy of the CLI with the length
assert removed computes 0x90b54dcb...273ec4 for the target, equal to the player, and the test exits 0.
