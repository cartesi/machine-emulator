# R1-R9-1: get_uarch_pristine_hash() reports the Keccak-256 pristine uarch hash on a SHA-256 machine

## What is asserted

For each hash function the emulator supports (`keccak256` and `sha256`), the test creates a fresh machine from the
harness `baremetal-minimal` configuration. That machine has never run, so its uarch is pristine. It then requires that
`m:get_uarch_pristine_hash()` either

- equals the machine's own pristine uarch subtree, `m:get_node_hash(UARCH_STATE_START_ADDRESS, UARCH_STATE_LOG2_SIZE)`, or
- refuses with an error for a hash function it has no precomputed value for.

It checks this on a local machine (C/Lua API `cm_get_uarch_pristine_hash`) and on a remote machine (JSON-RPC
`machine.get_uarch_pristine_hash`, through a spawned `cartesi-jsonrpc-machine` that is shut down at exit).
Keccak-256 is the control: if it does not match, the test exits 2.

Requirement (THREAT_MODEL R9): "Precomputed hashes, such as those of empty subtrees, must be correct for every
supported hash function."

Cause: `machine::get_uarch_pristine_hash()` (src/machine.cpp) is static and copies the build-time
`uarch_pristine_hash[]`, which `uarch/compute-uarch-pristine-hash.cpp` computes with Keccak-256 only.
`cm_get_uarch_pristine_hash(m, ...)` (src/cm.cpp) takes a machine but ignores that machine's hash function. The
JSON-RPC handler does the same.

## Facts for the reviewer (not part of the assertion)

- The C header (`src/cm.h`: "Gets the Keccak-256 hash of the pristine uarch state") and the JSON-RPC discovery
  document ("Returns the Keccak-256 hash of the pristine uarch state") both document the value as Keccak-256. So the
  output matches the API documentation. The finding depends on reading R9's "every supported hash function" as
  covering this per-machine query.
- The manual (doc/README.md, `hash_tree` entry) reserves `sha256` "for use with the ZK prover". It says a machine set
  up for the uarch can never be used with the ZK prover, and the reverse. The emulator refuses every uarch operation
  on a SHA-256 machine ("microarchitecture can only be used with hash tree configured with Keccak-256 hash
  function"). No transition, proof or verifier reads the constant under SHA-256. Internal uses
  (`collect_uarch_cycle_root_hashes`, the uarch replay) are Keccak-only.

## How to run

```sh
bugs/run.sh R1-R9-1
```

Runs in about a second. It needs only the in-tree build and `bugs/harness/work/configs/baremetal-minimal`.

## Expected output on audit/prt2 (exit 1)

```
local keccak256 machine: get_uarch_pristine_hash()=89ae34ba...d443d7, own pristine uarch subtree=89ae34ba...d443d7
local sha256 machine: get_uarch_pristine_hash()=89ae34ba...d443d7, own pristine uarch subtree=6da468a3...8002f8
VIOLATED: R9 (local): pristine uarch hash reported for a sha256 machine must be correct for sha256 or refused: ...
remote keccak256 machine: ... (match)
remote sha256 machine: get_uarch_pristine_hash()=89ae34ba...d443d7, own pristine uarch subtree=6da468a3...8002f8
VIOLATED: R9 (remote): ...
run.sh: R1-R9-1: exit 1 (bug present)
```

Once fixed, either by returning the pristine hash for the machine's hash function or by refusing the per-machine
call on non-Keccak machines, the test exits 0.
