# R7-MANHASHCOMP-1: the manual's output verifier executes proof files as Lua code

## What is asserted

`doc/recipes/verify-output-proof.lua` is the output verifier that doc/README.md prints under "Output
verification". The manual says it checks an output "from the settled state hash and those artifacts alone". It
reads each proof with

```lua
local function read_proof(name)
    return assert(loadfile(name, "t", {}))()
end
```

So it **runs** each proof file as a Lua chunk before it checks anything. The empty environment removes the globals,
but loops and the string methods (through the string metatable) are still available. `test.sh` runs the recipe
(`lua5.4 verify-output-proof.lua <state-hash> <proof> <proof> <output>`). Each run gets a CPU-time limit of 5 s
(an rlimit, not wall clock) and an address-space limit. It passes a crafted file as the outputs Merkle root proof:

| case | proof file | required | observed on audit/prt2 |
|---|---|---|---|
| control | `return {}` | rejected with an error | exit 1 (`attempt to index a nil value`), RSS ~14 MiB |
| 1 | `while true do end` (18 bytes) | rejected with an error within the CPU budget | killed by SIGXCPU (24) after 5 s of CPU: hangs |
| 2 | 46 bytes, `("x"):rep(1 << 29)` | no allocation far beyond the proof's size | peak RSS ~1 GiB above the control, before any check |
| 3 | 85 bytes, a loop that builds 2^20 strings of 1 GiB each | rejected without unbounded allocation | `lua5.4: not enough memory` at the 2 GB address-space limit |

The test exits 1 if any crafted case hangs, allocates 256 MiB or more beyond the control, runs out of memory, or
is accepted. It exits 0 when every crafted file is rejected promptly with bounded memory, which a data-only decoder
gives, for example `cartesi.fromjson(contents, "Proof")` as the CLI already uses for `.json` proofs. It exits 2 if
the control does not behave as expected.

The CLI (`src/cartesi-machine.lua` `read_proof`, default format `lua`) uses the same pattern
(`load(contents, filename, "t", {})()`) for `--cmio-advance-state=...,last_output_proof:<file>`. That file is
normally the operator's own artifact from the previous epoch, and this test does not assert on it.

## Requirement

- THREAT_MODEL.md section 4: "Logs and proofs are adversarial. A verifier must assume that every count, index,
  address, size, and hash it receives was chosen to fool it." and "Every path that carries such data must be
  memory-safe and bounded, and must report errors without terminating the process."
- Section 8, High: "A crash, hang, memory-safety defect or unbounded allocation in a component in the
  honest-operator role, caused by data from other parties that the honest operator may decline."
- Section 3, Support: "Medium when it would rate High or Critical in the role the component stands in for".
  (This test does not rate severity.)

## How to run

```sh
bugs/run.sh R7-MANHASHCOMP-1
```

It takes about 7 s and needs `lua5.4` and `python3`. The helper `runcase.py` applies the rlimits and reports
the child's exit, signal and peak RSS. Peak memory is about 1 GiB, for case 2.

## Expected output on audit/prt2

```
== case 1: proof file 'while true do end' (18 bytes), 5 s of CPU allowed
VIOLATION: the verifier never finished on the crafted proof; killed by signal 24 ...
== case 2: proof file of 46 bytes that builds a 512 MiB string
VIOLATION: a 46-byte proof made the verifier allocate ~1048000 KiB more than the control before any check ran
== case 3: proof file of 85 bytes that asks for 1 PiB of strings ...
VIOLATION: the verifier kept allocating until the address-space limit ... ('not enough memory') ...
FAIL: ...
run.sh: R7-MANHASHCOMP-1: exit 1 (bug present)
```
