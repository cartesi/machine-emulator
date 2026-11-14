## R1-R13-1

**Title.** The on-chain step verifier cannot be rebuilt from audited source. Regenerating machine-solidity-step
v0.17.0-test1 from audit/prt2 produces a `UArchStep.sol` that uses `TLB_NUM_SETS`, which nothing declares, so the
build fails.

**Severity.** High (preferred reading). Critical under the reading that a deployment must ship hand-edited verifier
code (see Rating).

### Problem

Commit afd5f9d ("fix: refuse out-of-range TLB indices in the uarch WRITE_TLB ecall") added this check to
`executeECALL` in `src/uarch-step.cpp`:

```cpp
if (set_index >= TLB_NUM_SETS || slot_index >= TLB_SET_SIZE) {
```

The commit message says "UArchStep.sol picks up the check when it is regenerated". It does not.

- The pinned translator `helper_scripts/generate_UArchStep.sh` adds the `EmulatorConstants.` prefix only to names
  that `src/EmulatorConstants.sol` defines (lines 40 and 60).
- `EmulatorConstants.sol` is built from `templates/EmulatorConstants.sol.template` and
  `helper_scripts/generate_EmulatorConstants.lua`. Neither one defines `TLB_NUM_SETS`. The template hand-codes
  `TLB_SET_SIZE = 256` and `TLB_SLOT_LENGTH = 32`.
- So the regenerated `src/UArchStep.sol:1090` keeps the bare identifier `TLB_NUM_SETS`, and solc 0.8.30 stops with
  `Error (7576): Undeclared identifier`.

The result is that the referee verifier for this emulator version cannot be built from audited source with the
pinned generator, in any order of the project's `generate-*` targets.

- To deploy it, someone has to edit the generated code or the template by hand, outside any audited source. The
  shared harness does this with `bugs/harness/solidity-step/patches/01-tlb-num-sets.sh`, which adds
  `uint64 constant TLB_NUM_SETS = 3;`.
- The only other buildable code is the released v0.17.0-test1 `UArchStep.sol`. It implements a different state
  transition function: `CM_MARCHID` 22 instead of 23, a different `UARCH_PRISTINE_STATE_HASH`, no TLB index check,
  and the old halt/overflow precedence. Deploying it would mix versions, against A6.

This breaks R13: "The uarch program, its pristine hash, and the verifier code that a deployment fixes on-chain must
be reproducibly buildable from audited source." It also removes the margin that A6 relies on, because the one
verifier that matches the emulator exists only as an unaudited hand edit.

### Component, role and area

- **Component.** machine-solidity-step v0.17.0-test1 regenerated from audit/prt2, meaning its generator, templates
  and the generated `UArchStep.sol` and `EmulatorConstants.sol`. AUDIT.md assigns it this role: "`machine-solidity-step`
  v0.17.0-test1, with its generated code and constants regenerated from `audit/prt2` | Referee verifier".
- **Root cause.** The uarch step source of the emulator, `src/uarch-step.cpp`. In the AUDIT.md table, "uarch program"
  is Honest operator. This source is also the input of the verifier generator.
- **Area.** Generating the on-chain step from C++, and the constants that the generated code uses.

### Location

- `src/uarch-step.cpp:890`, `executeECALL`, the `UARCH_ECALL_FN_WRITE_TLB` case. The constant itself is defined in
  `src/shadow-tlb.hpp:34` and exported as `CM_TLB_NUM_SETS` (`src/cm.h:106`) and `cartesi.TLB_NUM_SETS`
  (`src/clua-cartesi.cpp:337`).
- machine-solidity-step v0.17.0-test1 (pinned checkout `bugs/harness/work/solidity-step/released`):
  - `helper_scripts/generate_UArchStep.sh:40,60`: the list of constants that get the prefix.
  - `templates/EmulatorConstants.sol.template:28-30`: hand-coded TLB constants, with no `TLB_NUM_SETS`.
  - `helper_scripts/generate_EmulatorConstants.lua`: does not emit `TLB_NUM_SETS`.
  - `Makefile:53`: `build: generate-step generate-reset generate-send-cmio-response generate-constants generate-prod`
    followed by `forge build`.
- Regenerated output: `src/UArchStep.sol:1090`.

### Evidence and test

`bugs/R1-R13-1/` contains `test.sh` and `README.md`. Run the test with `bugs/run.sh R1-R13-1`. It takes about 1 s.
`MSS_DIR=<checkout> bugs/run.sh R1-R13-1` tests a candidate fix of the generator.

The test does the following, in a temporary directory, and modifies nothing shared:

1. It copies the untouched pinned checkout.
2. It runs `make generate-constants generate-step generate-reset generate-send-cmio-response generate-prod` with
   `EMULATOR_DIR` pointing at this repository's `src/`.
   - A `docker` shim runs `generate_EmulatorConstants.lua` with the in-tree Lua module instead of the emulator
     image. The harness checked that the two give identical constants.
   - The constants are generated first, which is the fixed point of the project's order and the more lenient
     choice. The project's literal `make build` order also fails.
3. It runs `forge build --offline --use 0.8.30`.
4. It checks that `TLB_NUM_SETS`, `TLB_SET_SIZE` and `TLB_SLOT_LENGTH` are defined in `EmulatorConstants.sol` when
   `UArchStep.sol` uses them, and that they equal `cartesi.TLB_NUM_SETS`, `TLB_SET_SIZE` and
   `SHADOW_TLB_SLOT_SIZE`.

It exits 1 on a compiler error or on a missing or wrong constant, 0 if the verifier builds and the constants agree,
and 2 on setup errors.

On audit/prt2 it prints the following and exits 1. The reviewer ran it three times and got the same result each
time.

```
== regenerated UArchStep.sol: TLB bound check (generated from src/uarch-step.cpp)
   1090:                set_index >= TLB_NUM_SETS
== forge build --use 0.8.30 (the project's build: src/ and the test/ contracts that import it)
   Error: Compiler run failed:
   Error (7576): Undeclared identifier.
       --> src/UArchStep.sol:1090:30:
FAIL (R13): the verifier regenerated from audited source with the pinned generator does not build
== TLB constants of EmulatorConstants.sol vs the emulator
   TLB_NUM_SETS: not defined in EmulatorConstants.sol (emulator: 3)
FAIL (R13): UArchStep.sol uses TLB_NUM_SETS, which EmulatorConstants.sol does not define
   TLB_SET_SIZE = 256 (emulator: 256) OK
   TLB_SLOT_LENGTH = 32 (emulator: 32) OK
run.sh: R1-R13-1: exit 1 (bug present)
```

The reviewer also ran two controls on a scratch copy of the pinned checkout, with
`uint64 constant TLB_NUM_SETS = <v>;` added to the template:

- **v = 3.** Line 1090 regenerates as `EmulatorConstants.TLB_NUM_SETS`, the build succeeds, and the test prints
  `PASS` and exits 0.
- **v = 4.** The build succeeds, but the test prints
  `FAIL (R13/A6): TLB_NUM_SETS = 4 in EmulatorConstants.sol, emulator has 3` and exits 1.

A fix on the emulator side that stops using an undeclared name would also make the test pass. The test flags a
missing constant only when the generated code uses it.

The harness log `bugs/harness/work/solidity-step/build-status.txt` records the same failure of the pure
regeneration.

Opus 5.5 found, proved and reviewed this candidate, with no fallback. It merges R1-A6-1 and R1-PREPARE-1.

### Trigger and reachability

No adversary is involved and no machine state is needed. Anyone who regenerates the step for this emulator version,
as AUDIT.md defines the referee verifier and as the project's `make build` does, hits the failure every time. That
includes every deployment that wants a verifier matching audit/prt2. The failure does not depend on any input
sequence.

### Rating

1. **Out of scope: no.**
   - The trigger is building the verifier from its pinned generator and this branch. It needs no API misuse, no
     untrusted snapshot, no host fault and no deployment that violates A1 to A8.
   - The exclusion "Defects that need the deployment to violate one of A1 to A8, unless the emulator's own behavior
     is what makes the obligation fail" does not apply. The build fails before any deployment exists. Here it is the
     emulator's change that makes A6 hard to meet.
2. **Role: Referee verifier.**
   - AUDIT.md: "`machine-solidity-step` v0.17.0-test1, with its generated code and constants regenerated from
     `audit/prt2` | Referee verifier". This clause covers the generator and its generated output.
   - Section 3: "Referee verifier. A verifier whose acceptance settles disputes, such as the on-chain verifiers."
   - The root cause in `src/uarch-step.cpp` is in the "uarch program" row (Honest operator). The defect is rated by
     the more critical role, Referee verifier. It is not a support component, so the Medium cap does not apply.
3. **High and Medium cases: High.**
   - The listed case: "A uarch program or verifier code fixed on-chain that cannot be reproducibly rebuilt, while
     what is deployed matches its audited source."
   - The verifier code fixed on-chain cannot be rebuilt from audited source. No deployed code yet differs from
     audited source in a way that changes what a verifier accepts.
   - The rule violated is R13: "The uarch program, its pristine hash, and the verifier code that a deployment fixes
     on-chain must be reproducibly buildable from audited source."
4. **Critical: not reached under this reading.**
   - Building the verifier is not one of the operations of the honest operator's path that section 2 lists.
   - It is not a rule violation at a reachable state.
   - No verifier accepts a wrong after-hash because of it.

**Two readings.**

- **Critical reading.** The High case is conditioned on "what is deployed matches its audited source". No audited
  source produces a buildable verifier that matches this emulator. So every deployment of this version must ship
  either:
  - a hand edit. Any value other than 3, or other drift, breaks A6 and R2.
  - the stale released step (marchid 22, old pristine hash, no TLB check). That breaks A6 and makes honest reset
    and step proofs disagree with the on-chain verifier, a completeness failure.

  Under this reading the qualifier fails, and a resulting version mix would be a violation of A6 and R13 that the
  emulator itself caused, so it would not be excluded.
- **What decides.** Whether the deployment process ships the regenerated verifier only from an audited, fixed
  generator, or ships the hand-patched or stale code. Today no audited source builds.

### Possible solution and risks

- **Generator side.** In machine-solidity-step, emit `TLB_NUM_SETS` from `generate_EmulatorConstants.lua`, as
  `cartesi.TLB_NUM_SETS`. Also emit `TLB_SET_SIZE` and `TLB_SLOT_LENGTH` (`cartesi.TLB_SET_SIZE`,
  `cartesi.SHADOW_TLB_SLOT_SIZE`) instead of hand-coding them in the template, so that nothing hand-written can
  drift from the emulator.
- **Ordering.** The generator should also make `generate-step` independent of the order of `generate-constants`. The
  translator reads the existing `EmulatorConstants.sol`, so the project's literal `make build` order, which runs
  `generate-step` first, fails on the first pass even with a fixed template.
- **Emulator side.** Add a CI job to the emulator that regenerates the step and runs `forge build` and the replay
  tests. Any change to `uarch-step.cpp` that uses a new constant would then fail at once.
- **Risks.**
  - A wrong `TLB_NUM_SETS` value in Solidity would make the on-chain verifier diverge from the emulator on the
    WRITE_TLB ecall, either accepting or refusing differently. The value must come from the emulator, not be
    hand-typed.
  - Regenerating also changes `CM_MARCHID` and `UARCH_PRISTINE_STATE_HASH`. Dave's fixtures and the
    machine-solidity-step tests that expect the old values, `testCmMarchId` and two mock tests on halt/overflow
    precedence, need updating. Those are stale expectations, not separate defects.

### Risk of not fixing it

The audited emulator version has no verifier that can be built from audited source. A deployment must either
hand-patch the generated Solidity, which leaves unaudited code that a referee verifier relies on, or deploy the stale
released step. The stale step implements a different state transition function, with a different marchid and
pristine hash, which mixes versions (A6) and makes the honest operator's proofs fail on-chain. Nobody needs to
trigger it: every regeneration fails. The mitigation outside the code is to release a fixed machine-solidity-step
together with this emulator version and audit it.
