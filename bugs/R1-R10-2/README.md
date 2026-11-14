# R1-R10-2: Solidity step rejects uarch accesses to the last leaf of the address space

**Component:** machine-solidity-step `Memory.sol`, `validateStrideLength`. The same file appears in the released
v0.17.0-test1, in the regenerated step (`bugs/harness/work/solidity-step/step/src/Memory.sol`) and in Dave's
`machine/step`. The step reaches it through `AccessLogs` and `UArchStep`. It is a referee verifier.

```solidity
uint64 constant MAX_STRIDE = MAX_SIZE - 1;          // MAX_SIZE = 2^59 leaves
assert(Stride.unwrap(stride) * s < MAX_STRIDE);     // validateStrideLength
```

The 32-byte leaf at `0xffffffffffffffe0..ff` has stride `2^59 - 1` with `s = 1`. The assertion therefore fails
with `Panic(0x01)` for any access to it. The correct bound is `stride * s + s <= 2^59`.

## What the test asserts

Each probe uses a fresh machine (1 MiB RAM). Its uarch is about to execute a single load from the top leaf
(`ld x1,-8(x0)` reads `0xfffffffffffffff8`, `lw x1,-32(x0)` reads `0xffffffffffffffe0`). For each probe the test
checks the following.

1. The native uarch and the log producer (`m:log_step_uarch()`) accept the step. The address is unmapped, so the
   load reads zero; this is not a uarch trap.
2. The C++ verifier (`verify_step_uarch`) returns the same after-hash.
3. **Required:** the regenerated `StepVerifier.step` accepts the same log with the same after-hash. It runs on a
   private anvil that the test starts on a random port in 30000-39999 and stops at the end. The shared harness
   contracts are used unchanged.

The control loads from one leaf lower (`0xffffffffffffffd8`). All three paths must agree on it, otherwise the test
exits 2. Stores to the top leaf are not probed because the native uarch refuses them (write to an unmapped
address).

Requirements quoted from THREAT_MODEL.md:

- R2: "Wherever two of the following reach the same position, they must agree on its canonical hash. ... Every log
  producer and every log verifier. The on-chain verifiers."
- R3: "A verifier must never turn a log defect into an accepted no-op, nor a semantic no-op into a rejection."

The test does not argue whether the state is reachable or how severe the defect is; that is left to the reviewer.
The hunter's argument is that the pristine uarch never addresses the top leaf (section 8 High: "A divergence
between paths only at demonstrably unreachable states").

## Run

```sh
bugs/run.sh R1-R10-2
```

It takes about 10 s. It needs the in-tree emulator, the StepVerifier artifact in `bugs/harness/work/evm/out/`
(built by `bugs/harness/solidity-step/evm/start.sh`), `anvil`, `cast`, `jq` and `curl`.

## Expected output on audit/prt2

```
control ld x1,-40(x0) [0x..ffd8]   native ok / C++ ACCEPTED / EVM ACCEPTED, same after-hash
ld x1,-8(x0)  [0xfffffffffffffff8] native ok / C++ ACCEPTED / EVM REVERTED: panic: assertion failed (0x01)
lw x1,-32(x0) [0xffffffffffffffe0] native ok / C++ ACCEPTED / EVM REVERTED: panic: assertion failed (0x01)
VIOLATED: R2 ... R3 ... 2 divergence(s) of 2 probes
run.sh: R1-R10-2: exit 1 (bug present)
```

Exit codes:

- 0: the bug is fixed. All paths agree, either because the EVM accepts with the native after-hash or because the
  native path refuses the step.
- 1: the bug is present.
- 2: harness or setup error.
