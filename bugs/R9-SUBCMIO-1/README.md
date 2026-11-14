# R9-SUBCMIO-1: creation accepts a machine at an rx-rejected manual yield whose revert root hash is zero

## Requirement

THREAT_MODEL.md, R4 (Honest completeness):

> Every reproducible configuration that the emulator accepts, using the deployment's hash function and holding only
> register values that the RISC-V specification and the manual allow, yields a machine on which this rule holds. A
> configuration that would not is rejected when the machine is created.

## What the test asserts

`test.lua` creates machines with `cartesi.machine(config)` from a reproducible Keccak-256 configuration (1 MiB RAM)
whose processor registers hold `iflags.Y = 1` and `htif.tohost = (HTIF_DEV_YIELD << 56) | (HTIF_YIELD_CMD_MANUAL << 48)
| (reason << 32)`:

1. control, reason = rx-accepted. This case must pass, otherwise the test exits 2. The leaf at the next mcycle
   boundary from `collect_mcycle_root_hashes` and the after-hash of the closing uarch reset
   (`log_reset_uarch` then `verify_reset_uarch`) both equal the machine's root hash.
2. reason = rx-rejected. No configuration field sets the revert root hash, so it is 32 zero bytes. The requirement
   holds if creation raises. If the machine is created, the collector's leaf and the reset's after-hash must not be
   the all-zero hash, because 0x00..00 is the content hash of no state. No uarch trajectory, node or step proof can
   start from it. The test also records whether `collect_uarch_cycle_root_hashes` accepts a made-up tail ending at
   that zero hash. It does, because it checks only the last entry. This result is informational and does not decide
   the outcome.

The test exits 1 if case 2 is accepted and produces the zero hash.

## Run

```sh
bugs/run.sh R9-SUBCMIO-1
```

## Expected output on audit/prt2

```
control (manual yield, accepted): accepted; root 26419c7c81fa7c26; revert root hash 0000000000000000; collect_mcycle_root_hashes leaf 26419c7c81fa7c26 (1 leaves); verify_reset_uarch after-hash 26419c7c81fa7c26; collect_uarch_cycle_root_hashes with made-up tail: n/a
VIOLATED: R4 configuration clause: iflags.Y=1, tohost = manual yield rx-rejected: accepted; root 4f44a2c7533d14f6; revert root hash 0000000000000000; collect_mcycle_root_hashes leaf 0000000000000000 (1 leaves); verify_reset_uarch after-hash 0000000000000000; collect_uarch_cycle_root_hashes with made-up tail: accepted; the canonical hash at the next mcycle boundary is 32 zero bytes, the hash of no state
VIOLATED: R4: a configuration whose machine cannot satisfy R4 must be rejected at creation
run.sh: R9-SUBCMIO-1: exit 1 (bug present)
```

There are two possible fixes, and the test exits 0 with either one:

- creation validates `iflags.Y`/`htif.tohost` against the revert root hash and rejects the configuration;
- the rejection exception never yields a hash that is not a state's content hash.

The test runs in under a second. Loading a stored machine directory is a separate path, and the test does not
exercise it.
