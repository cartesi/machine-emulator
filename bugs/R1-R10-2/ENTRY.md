## R1-R10-2

**Title.** Off-by-one in `Memory.validateStrideLength` makes the on-chain step verifier revert on any uarch access to
the last 32-byte leaf of the address space, which the native uarch, the log producer and the C++ verifier accept.

**Severity.** High

### Problem

`Memory.validateStrideLength` in machine-solidity-step checks `stride * s < MAX_STRIDE`, where
`MAX_STRIDE = MAX_SIZE - 1 = 2^59 - 1` and `s` is the region size in 32-byte leaves. The correct bound for a region
inside the 2^59-leaf tree is `stride * s + s <= 2^59`. Because `s` is a power of two and `2^59 - 1` is odd, the check
rejects exactly one region: the single leaf at stride `2^59 - 1`, bytes `0xffffffffffffffe0..0xffffffffffffffff`.
Every `readLeaf`, `writeLeaf`, `readWord` and `writeWord` of `AccessLogs` builds its region through
`Memory.regionFromStride`, so a uarch step whose log accesses that leaf reverts with `Panic(0x01)`.

The native uarch and the C++ verifier define a successor for such a step. A uarch load from an unmapped address in
the top leaf reads zeros and completes, and `verify_step_uarch` accepts the log with the native after-hash. The
on-chain verifier refuses the same log. This breaks R2: "Wherever two of the following reach the same position, they
must agree on its canonical hash. ... Every log producer and every log verifier. The on-chain verifiers." The address
of the access is a condition on the authenticated state, not on the log, so the revert also turns semantics into a
rejection (R3: "Conditions on the authenticated state or on the referee parameters are semantics. They define the
successor").

It does not break the goal of section 1. The pristine uarch never accesses the top leaf from a reachable state (see
"Trigger and reachability"), so the honest operator never needs a proof there. It removes a margin: the deployed
verifiers and the off-chain paths disagree on which states have a successor.

### Component, role and area

machine-solidity-step v0.17.0-test1, `src/Memory.sol` (unchanged in the released tag, in the step regenerated from
`audit/prt2`, and in Dave's `machine/step`, all byte-identical). It is reached through `AccessLogs.sol` and
`UArchStep.sol`, which Dave's `CartesiStateTransition` calls. AUDIT.md component table: "`machine-solidity-step`
v0.17.0-test1, with its generated code and constants regenerated from `audit/prt2` | Referee verifier". Area: memory
region validation of the access-log replay.

### Location

- `src/Memory.sol` of machine-solidity-step: `uint64 constant MAX_STRIDE = MAX_SIZE - 1;` (line 66) and
  `validateStrideLength` (lines 98-104, `assert(Stride.unwrap(stride) * s < MAX_STRIDE);`), called by
  `regionFromStride` (line 36).
- Callers: `src/AccessLogs.sol` (`readLeaf` line 83, `writeLeaf` line 110, `readWord` line 128, `writeWord` line
  154, line 216). Harness copies: `bugs/harness/work/solidity-step/{released,regenerated,regenerated-patched}/src/`
  and `bugs/harness/work/dave/{released,patched}/machine/step/src/Memory.sol`, md5 `cde00923a8c6954c1d4addc67d1f6ba1`
  for all.

### Evidence and test

`bugs/R1-R10-2/` contains `test.lua` and `README.md`. Run `bugs/run.sh R1-R10-2` (about 10 s). It needs the in-tree
emulator, the shared StepVerifier artifact `bugs/harness/work/evm/out/StepVerifier.sol/StepVerifier.json`, `anvil`,
`cast`, `jq` and `curl`. The test starts its own anvil on a random port in 30000-39999, installs the regenerated
`StepVerifier` runtime code with `anvil_setCode`, and kills that anvil at the end.

For each probe it builds a fresh machine (1 MiB RAM), writes one load instruction at `0x80000000` and sets `uarch_pc`
there. It then runs `m:log_step_uarch()`, `cartesi.machine:verify_step_uarch(before, log)`, and `StepVerifier.step`
on the EVM. It requires all three to give the native after-hash, or the native path to refuse the step. The control,
`ld x1,-40(x0)` at `0xffffffffffffffd8` (one leaf lower), must verify on all three paths, or the test exits 2. The
probes are `ld x1,-8(x0)` (address `0xfffffffffffffff8`) and `lw x1,-32(x0)` (address `0xffffffffffffffe0`). Stores
to the top leaf are not probed because the native uarch traps on them.

On audit/prt2 it prints, on each of two runs by the reviewer (exit 1 both times):

```
control ld x1,-40(x0) [0x..ffd8]   native/log producer: ok, after-hash 32bdd705...16df2f
                                   C++ verify_step_uarch: ACCEPTED, same after-hash
                                   EVM StepVerifier.step: ACCEPTED, same after-hash
ld x1,-8(x0)  [0xfffffffffffffff8] native/log producer: ok, after-hash af91d506...798d11
                                   C++ verify_step_uarch: ACCEPTED, same after-hash
                                   EVM StepVerifier.step: REVERTED: execution reverted: panic: assertion failed (0x01) data=0x4e487b71...01
    (revert is Panic(0x01): Memory.validateStrideLength assertion)
lw x1,-32(x0) [0xffffffffffffffe0] native/log producer: ok, after-hash e90de323...07cacb9
                                   C++ verify_step_uarch: ACCEPTED, same after-hash
                                   EVM StepVerifier.step: REVERTED: execution reverted: panic: assertion failed (0x01) data=0x4e487b71...01
    (revert is Panic(0x01): Memory.validateStrideLength assertion)
VIOLATED: R2: ... 2 divergence(s) of 2 probes
run.sh: R1-R10-2: exit 1 (bug present)
```

The test exits 0 after either fix: a Solidity bound that admits the top leaf, or a native uarch that traps on the
access. Found by the R10 hunter (duplicate R1-R3-2 merged), proved and reviewed on Opus 5.5. No fallback was used.

### Trigger and reachability

Trigger: a uarch step from a before-state whose uarch executes a load (or fetch) with its effective address in
`0xffffffffffffffe0..0xffffffffffffffff`. Any party could submit such a step to the referee, but only from a
before-state that the referee would accept (A1). The test builds that state through the machine API
(`write_reg("uarch_pc", 0x80000000)` plus a hand-written instruction).

Such a state is unreachable from any valid template:

- At every mcycle boundary of a reachable state the uarch is pristine (valid template; the closing reset), and the
  guest cannot address the uarch state or uarch RAM (R8; the uarch ranges are registered with `pmas = false`). So
  the uarch registers, its pc included, follow the pristine program, which is fixed code in uarch RAM.
- The pristine program addresses only fixed regions: its own RAM (`0x600000..0x800000`), the uarch shadow
  (`0x400000`), the processor shadow registers (`0x0..0x1000`), the shadow TLB (`0x1000..0x7000`) and the PMA array
  (`0x10000..0x11000`). It addresses main-processor memory only through `read/write_memory_word` after `find_pma`
  matched a PMA, or through a TLB hit. On every hit, `uarch-bridge-state-access.hpp`'s `do_verify_cold_tlb_slot` runs
  `shadow_tlb_verify_slot`, which requires the physical page to lie inside the slot's memory PMA
  (`interpret.cpp:1081`, `1197`, `5646`).
- `machine_address_ranges::check` refuses any range whose start or end exceeds `AR_ADDRESSABLE_MASK` ("must use at
  most 56 bits to be addressable"). So no PMA, and no reachable TLB entry, reaches the top leaf.
- A main-processor access to `0xfff...f8` matches no PMA, so it raises an access fault without reading memory.

Hence no input sequence from any valid template makes the uarch touch the top leaf, and the honest operator never
needs to prove such a step.

### Rating

1. Out of scope: no. The trigger is a before-state, not a deliberate state change whose effect is at issue ("The
   effect of a deliberate state change made through the machine API" excludes what the change does to the machine,
   not a verifier's disagreement on the resulting state; R10 requires verifiers to be safe "on every before-state").
   The defect needs no untrusted call to the machine API, no deployment violation of A1 to A8, no snapshot the
   emulator did not write, and no reload that O2 does not guarantee.
2. Role: the component is `machine-solidity-step` `Memory.sol`, whose AUDIT.md role is "Referee verifier". Section 3
   defines it as "A verifier whose acceptance settles disputes, such as the on-chain verifiers". That clause covers
   this component directly. Dave's `CartesiStateTransition` (Referee model) only inherits it from this copy:
   "A defect it only inherits from a copy of a verifier that it calls is rated by that copy's role".
3. High and Medium cases: High, "A divergence between paths only at demonstrably unreachable states." The native
   uarch and log producer, the C++ log verifier and the on-chain verifier are all paths that R2 lists ("Every log
   producer and every log verifier. The on-chain verifiers."). At this state the first three agree on an after-hash
   and the on-chain verifier refuses to produce one. The state is demonstrably unreachable (argument above).
4. Critical: not applicable. No reachable state or step on the honest operator's path triggers it, so R4 ("From any
   reachable state ... log the transition so that it verifies") and R2 at reachable states hold.

Second reading: the first High bullet defines a verifier's misbehaviour as "being nondeterministic, accepting a wrong
or second after-hash ..., not being memory-safe, or being unbounded", which does not list rejecting a log. R3 also
says "R4 asks for proofs only from reachable states, so refusing a trap from an unreachable state never breaks it."
If refusing a valid log at an unreachable state were not a divergence between paths, the defect would violate no
rule and be Low. This review prefers High. The divergence bullet is separate from the misbehaviour list and is not
limited by it. The R3 sentence covers refusing a uarch trap, but here the native uarch does not trap: it defines a
successor. The deciding facts would be whether the threat model counts one path rejecting where another defines a
successor as a divergence, and whether the manual meant the uarch memory map to allow reads of unmapped addresses.

### Possible solution and risks

Fix the bound in `validateStrideLength`, for example `assert(uint256(Stride.unwrap(stride)) * s + s <= MAX_SIZE);`.
For an aligned region this equals `stride * s < MAX_SIZE`. Widening to `uint256` keeps an oversized stride from a
crafted log from reverting with an arithmetic panic instead of the assertion. This changes deployed verifier code,
so it needs a new step release and a Dave rebuild. It changes no transition at a reachable state. Risk: low. It
admits exactly one more region, the top leaf. The proof replay for that leaf (index `2^59 - 1`) was not exercised
past the assertion in this review, so the fix needs a replay test that reads the top leaf and checks the native
after-hash.

Another option is to make the native uarch and the C++ verifier trap on any uarch access outside the declared ranges.
That would also restore agreement, but it changes the off-chain transition function and is more invasive.

### Risk of not fixing it

No current exposure. The pristine uarch never reaches the top leaf from a reachable state, so neither the honest
operator nor an adversary can use the divergence against a deployment. What remains is a lost margin: the on-chain
verifier and the off-chain implementations disagree at some before-states. A future uarch change, a new PMA layout
near the top of the address space, or a relaxed 56-bit limit would turn it into a completeness failure (Critical by
R4) without any change to the Solidity code. Keeping the 56-bit address-range limit and the TLB slot verification
keeps it unreachable.
