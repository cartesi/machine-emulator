## R1-A7-1

**Title.** The released Dave clocks give the uarch-level commitment a budget sized for average uarch density. A guest
running dense heavy instructions makes the honest leaf build take 1.5 to 6 times `COMMITMENT_BUDGET`.

**Severity.** Critical. Under an alternative reading of section 3 it is Medium (see Rating).

### Problem

Dave v3.0.0-alpha.7 gives the honest claim `COMMITMENT_BUDGET` = 120 minutes to build the commitment it joins an
inner (uarch-level) tournament with. `ClockBudgets.sol` says: "joining an inner tournament first takes `commitment`
seconds to build the commitment". The parent's refill and the root allowance cover only that budget plus inclusions.
Any time past it is charged as join lateness (`Tournament.joinTournament` -> `Clock.initializePausedAt`). It comes
out of the censorship budget `C`, and the join reverts with `TournamentIsClosed` once the child's allowance has run
out.

With `log2step = [38, 0]`, the level-1 commitment covers one level-0 leaf: 2^18 mcycles, with one hash per executed
uarch cycle. Dave sized the budget from a reference leaf build rate of 173 mcycles/s, measured on a workload of 566
executed uarch cycles per mcycle (`docs/measurements/constants.md`). `docs/dimensioning.md` states the design choice:
"Coordinates are dimensioned to the worst case. Clocks are dimensioned to the average case", and "leaf-level dense
build within the commitment budget | aggregate | trusted app | average density". Dave rests this on an assumption
that the application developer is "trusted specifically to keep input-reachable behavior disputable".

The threat model assumes no such thing. The guest may be taken over by any input and "run any instruction stream at
any privilege level" (section 4). A correctly designed application bounds only its mcycle usage (section 2). R12 puts
the per-cycle worst case on the deployment: "The total cost of an epoch is the application's mcycle usage times these
bounds. Bounding that usage is the application's job, and sizing the deployment for it is the deployment's job
(A7)". The worst-case cost per mcycle of a uarch-level claim is far above the average Dave priced:

- `sfence.vma` in S-mode: 17,329 uarch cycles per mcycle, 28-31 times the control's host cost;
- `fdiv.d` in U-mode, which needs no privilege: 4,487 uarch cycles per mcycle, 7.2-8.0 times the control.

Scaled to Dave's own reference host with no hardware slack, one leaf build takes about 11.3-12.4 h for `sfence.vma`
and about 2.9-3.2 h for `fdiv.d`, against a 2 h budget. With the slack of 2 that Dave's own derivation assumes, it
takes about 23 h and 6 h.

What this does to the security goal, a completeness failure: "The honest operator ... cannot respond in time". The
dispute adversary chooses where to diverge (section 7: "Steer the dispute to any position of the honest
computation"). It can therefore put the inner tournament on a dense leaf.

- On testnet constants (`C` = 8 h, child allowance about 10.3 h), one `sfence.vma`-dense leaf cannot be joined in
  time on the reference host.
- On mainnet constants (`C` = 1 week), each forced delegation over a dense leaf costs the honest claim about 9-21 h
  of `C`, beyond the 2 h the refill restores. That time is not available for the censorship that `C` is meant to
  absorb ("A correct commitment must survive `censorship` seconds of adversarial delay in total"). An adversary that
  censors within the dispute clocks, plus one dense delegation, or a series of dense delegations forced through
  Sybils, exhausts the honest clock. The honest claim then loses by timeout.

### Component, role and area

- Dave v3.0.0-alpha.7 released arbitration constants and clock model. AUDIT.md role: "Referee model, as the deployed
  referee. Audit the released constants".
- The cost they fail to cover is that of `collect_uarch_cycle_root_hashes`, the uarch-level claim builder that the
  Dave node calls for dense leaf builds (`cartesi-rollups/node/src/engine/machine_stf.rs`, `big_cycle_roots`).
  AUDIT.md role: Honest operator.
- Area: dispute clock sizing (A7) against the R12 worst-case cost of a uarch-level claim.

### Location

- `bugs/harness/work/dave/released/prt/contracts/src/arbitration-config/ArbitrationConstants.sol`:
  `COMMITMENT_BUDGET = 120 minutes`, `log2step` `[38, 0]`, `height` `[54, 38]`.
- `.../prt/contracts/src/arbitration-config/ClockBudgets.sol`: `refill`, `maxAllowance`.
- `.../prt/contracts/script/Deployment.s.sol`: censorship budget 1 week (mainnet), 8 hours (testnet), 0 (devnet);
  inclusion budget 5 minutes.
- `.../prt/contracts/src/tournament/Tournament.sol`: `joinTournament` (`TournamentIsClosed`,
  `initializePausedAt`), `_isClosed`.
- Rationale: `.../docs/dimensioning.md` ("The rule", "Worked examples") and `.../docs/measurements/constants.md`.
- Emulator, honest operator: `collect_uarch_cycle_root_hashes` (its cost is what the uarch semantics require; it is
  not itself the defect).

### Evidence and test

`bugs/R1-A7-1/` contains:

- `test.lua`, the test;
- `README.md`;
- `guests/ctrl.S`, `guests/fdiv.S` and `guests/sfence.S`: bare-metal guests. Each enters a loop in U-mode (`ctrl`:
  `addi`; `fdiv`: `fdiv.d`) or in S-mode (`sfence`: `sfence.vma`) with bare translation. The test builds them at run
  time with `bugs/harness/baremetal/build.sh`.

Run it with `bugs/run.sh R1-A7-1`. It takes about 20 s and needs the toolchain image for the guest build.

The test parses `COMMITMENT_BUDGET`, `log2step`, the reference rate, the density and the hardware slack from the
released Dave sources. It then measures, for each guest:

- the exact number of executed uarch cycles per mcycle (a deterministic count);
- the host cost per mcycle of `collect_uarch_cycle_root_hashes`, in interleaved rounds. Only the ratio R to the
  control is used, so the host's speed cancels out.

It projects one 2^18-mcycle leaf on Dave's reference host as `R * min(1, D_ctrl/566) * 2^18 / 173 s`, with no
hardware slack. It then asserts that the projection is at most `COMMITMENT_BUDGET` for both dense guests.

On audit/prt2 it exits 1. The reviewer ran it 3 times, and every run exited 1. A typical run prints:

```
Dave released: COMMITMENT_BUDGET 120 min, log2step [38, 0] -> one leaf = 2^18 mcycles
Dave reference: 173 mcycles/s at 566.0 usteps/mcycle (hardware slack 2) -> average-density leaf build 1515 s (0.42 h), 3031 s with slack
guest    usteps/mc ratio(cnt)  ms/mc(host)    ratio(host)  leaf h slack1  leaf h slack2
ctrl           544       0.96         9.25           1.00           0.40           0.81
sfence       17329      30.62       262.04          28.33          11.46          22.93
fdiv          4487       7.93        69.27           7.49           3.03           6.06
budget: 2.00 h (COMMITMENT_BUDGET)
VIOLATED: A7/R12: honest uarch-level claim over one 2^18-mcycle leaf of a guest running sfence.vma in S-mode ... projects to 11.46 h ... with NO hardware slack ...
VIOLATED: A7/R12: honest uarch-level claim over one 2^18-mcycle leaf of a guest running fdiv.d in U-mode ... projects to 3.03 h ... with NO hardware slack ...
run.sh: R1-A7-1: exit 1 (bug present)
```

The margins are wide:

- The threshold is a host ratio of about 4.9. `sfence.vma` measures 28-31 and `fdiv.d` measures 7.2-8.0.
- A purely count-based projection, which does not depend on timing, also fails: about 12.9 h for `sfence.vma` and
  3.3 h for `fdiv.d`.

The test passes once the released clocks or strides are sized for the worst-case density. That fix would be a larger
`COMMITMENT_BUDGET`, or a smaller level-0 stride.

The test does not drive the chain. In particular, it does not show `TournamentIsClosed` on an honest late join; that
consequence is derived from the contract code above. A1 to A8 compliance of the clock arithmetic itself was not
re-checked. The candidate was found, proved and reviewed by Opus 5.5, with no fallback model.

### Trigger and reachability

The trigger needs two parties.

- A guest region of 2^18 mcycles that is dense in heavy uarch instructions. Any input may produce it in an
  otherwise correctly designed application: section 4 says an input "may then run any instruction stream at any
  privilege level". The input stays within the application's mcycle bound, which `imcyclemax` enforces. For the
  U-mode `fdiv.d` case, an application that legitimately runs floating-point-heavy user code is enough. No
  compromise is needed.
- A dispute adversary that posts a claim diverging inside that region. Section 7 allows it to "Steer the dispute to
  any position of the honest computation, and force the honest claim through a logarithmic number of matches".

Both are reachable, and no unreachability argument applies.

### Rating

1. Out of scope: no.
   - The exclusion "Defects that need the deployment to violate one of A1 to A8" has two carve-outs, and both cover
     this case: "unless the emulator's own behavior is what makes the obligation fail, such as a worst-case cost ...
     larger than the deployment was sized for, or unless an implementation of the referee model is what violates it
     (section 3)". Dave is that implementation; AUDIT.md: "Referee model, as the deployed referee. Audit the released
     constants".
   - "Average-case performance that does not change the worst-case cost of any operation listed in R12" does not
     apply. The finding is about the worst case.
   - "An application that is not correctly designed" does not apply. Section 2 requires a correctly designed
     application only to bound "its own mcycle usage", not its uarch density. Dave's trusted-density assumption is
     outside the threat model.
2. Role: two components show the defect.
   - Dave's released constants play "Referee model" (section 3).
   - The overrunning operation, `collect_uarch_cycle_root_hashes`, plays "Honest operator" (AUDIT.md table).
   - Section 3: "A defect is rated by the most critical role among the components that show it."
3. High and Medium cases: none fits on the preferred reading.
   - The High case on constant-factor cost increases needs "a defect that lets the guest ... multiply the worst-case
     cost ... compared with the same operation without the defect". Here the cost is the one "the specified
     semantics require", so there is no emulator defect.
   - The defect is the mismatch between that cost and the sizing.
4. Critical: two clauses apply.
   - Section 8 lists as Critical "An operation listed in R12 whose worst-case cost a guest can make unbounded,
     super-linear, or larger than what the deployment was sized for". R12 lists "a uarch-level claim".
   - It also violates A7: "The dispute constants and clocks leave room for the honest claim to play the logarithmic
     number of matches that a tournament forces on it, at the worst-case costs of R12". This happens at a reachable
     state, on the honest operator's path ("Computing claims"). The resulting timeout is a completeness failure under
     section 1.

Alternative reading: Medium. Section 3 says of the referee model: "A defect that only changes how long a claim may
take to respond, or only crashes or stalls the model ... is rated as support". If undersized clocks in Dave count as
"only" changing how long a claim may take to respond, the defect is rated as support. Section 3 then gives Medium,
because it "would rate High or Critical in the role the component stands in for".

Facts that decide between the readings:

- whether the support clause covers the deployed referee's clock sizing, or only clock differences in a model whose
  clock values are not normative (section 5: "neither are its clock values");
- whether the "worst-case cost larger than what the deployment was sized for" case counts the honest-operator
  builder as a component that shows the defect.

The reviewer prefers Critical. The goal's premise, "on the resources the deployment was sized for", fails exactly
here, and AUDIT.md tells auditors to audit the released constants as the deployed referee. Both readings rate the
defect Medium or above.

### Possible solution and risks

Size the clocks for the worst-case density of R12 rather than the average. Options:

- Raise `COMMITMENT_BUDGET` to cover a leaf of `sfence.vma`-class instructions. That is about 30 times the
  average-density build, plus slack.
- Shrink the level-0 stride, for example with more levels or a smaller `log2step(0)`, so that a worst-case leaf fits
  the current budget.
- Have the emulator lower the worst-case uarch cost of the heaviest instructions. That would be a new protocol
  version (R13).
- Alternatively, make the trusted-density assumption an explicit deployment obligation, with tooling that enforces
  it.

Risks:

- A larger budget lengthens every dispute and delays settlement.
- More levels change the contract-client compatibility boundary ("Coordinated-bump checklist" in constants.md) and
  the root-slowdown derivation.
- Changing uarch costs changes the pristine uarch hash and the step.

### Risk of not fixing it

- On testnet constants, an adversary that controls any input able to drive a guest into a 2^18-mcycle
  `sfence.vma`-dense region can make the honest claim unable to join the inner tournament in time on the reference
  host. It can do the same with an application whose own U-mode code is `fdiv`/`fsqrt`-dense, combined with
  censorship within `C`. A dishonest claim then wins the epoch.
- On mainnet, the same overrun silently consumes the week-long censorship budget at every forced dense delegation.
  The honest claim is left exposed to censorship the deployment claims to survive.
- The only mitigation outside the code is Dave's documented trust assumption: that validators defend only
  applications whose input-reachable behavior stays near average density. Nothing in the protocol checks or
  enforces it.
