# R1-A7-1: the leaf commitment budget is sized for average uarch density, not the worst case

## What is asserted

The released Dave v3.0.0-alpha.7 constants give the honest operator `COMMITMENT_BUDGET` = 120 min to build a
uarch-level (level-1) commitment (`ClockBudgets.sol`: "joining an inner tournament first takes `commitment` seconds
to build the commitment"). With `log2step = [38, 0]` that commitment covers one level-0 leaf, 2^(38-20) = 2^18
mcycles, with one hash per uarch cycle. Dave sized this budget from a measured leaf build rate of 173 mcycles/s on a
workload of 566 uarch cycles per mcycle (`docs/measurements/constants.md`; `docs/dimensioning.md`: "Clocks are
dimensioned to the average case").

The test builds three small bare-metal guests (`guests/*.S`, built into a temp dir by
`bugs/harness/baremetal/build.sh`):

| guest | loop | privilege |
|---|---|---|
| `ctrl` | integer `addi` (control, close to Dave's average density) | U |
| `fdiv` | `fdiv.d` | U (needs no privilege) |
| `sfence` | `sfence.vma` | S (guest kernel code) |

For each guest it measures:

* the exact number of uarch cycles per mcycle (a count, which is deterministic);
* the host cost per mcycle of the honest uarch-level claim builder, `collect_uarch_cycle_root_hashes` (bundled per
  mcycle, as the node does). The guests run in interleaved rounds in one process, and only the ratio R to the
  control is used, so the host's speed cancels out.

It then projects the build of one 2^18-mcycle leaf on Dave's own reference host:
`R * min(1, D_ctrl/566) * 2^18 / 173 s`. That uses no hardware slack, which is the reading most favorable to
the deployment; Dave's own derivation assumes slack 2. The test asserts that the projection is at most
`COMMITMENT_BUDGET` for both dense guests. All constants are parsed from the released sources in
`bugs/harness/work/dave/released`, so a re-sized deployment (larger budget or smaller leaf stride) makes the test
pass.

## Requirement

THREAT_MODEL.md:

* A7: "The dispute constants and clocks leave room for the honest claim to play the logarithmic number of matches
  that a tournament forces on it, at the worst-case costs of R12 ... No rule of the referee may make the honest
  claim lose by timeout while it acts within its own clock."
* Section 8, Critical: "An operation listed in R12 whose worst-case cost a guest can make unbounded, super-linear,
  or larger than what the deployment was sized for." R12 lists "a uarch-level claim".
* Section 4: "Any input may take control of the firmware, the kernel, ... It may then run any instruction stream at
  any privilege level."

## How to run

```sh
bugs/run.sh R1-A7-1        # about 20 s; needs docker (toolchain image) for the guest build
```

## Expected output on audit/prt2

Exit 1. Typical numbers, which were stable over 5 runs:

```
guest    usteps/mc ratio(cnt)  ms/mc(host)    ratio(host)  leaf h slack1  leaf h slack2
ctrl           544       0.96         8.94           1.00           0.40           0.81
sfence       17329      30.62       274.66          30.73          12.44          24.87
fdiv          4487       7.93        71.61           8.01           3.24           6.48
budget: 2.00 h (COMMITMENT_BUDGET)
VIOLATED: A7/R12: ... sfence.vma in S-mode ... projects to 12.44 h ... with NO hardware slack ...
VIOLATED: A7/R12: ... fdiv.d in U-mode ... projects to 2.97-3.24 h ... with NO hardware slack ...
run.sh: R1-A7-1: exit 1 (bug present)
```

Margins:

* For `sfence` (S-mode), the host-cost ratio is about 29-31 and fails above about 5, so the projection is about 6x
  over budget with no slack and about 12x with Dave's slack 2.
* For `fdiv` (U-mode), the ratio is about 7.3-8.0 against the same threshold of about 5: about 1.5x over budget
  with no slack and about 3x with slack 2.

On this host, absolute cost is about 9 ms per mcycle for the control, 275 ms for sfence and 70 ms for fdiv. That
puts a whole leaf at about 20 h for sfence and 5 h for fdiv.

## Notes for the reviewer

* Host cost per mcycle is not proportional to uarch cycles. It has a per-mcycle part: R is 8 for fdiv against a
  count ratio of 8.2, and 30 for sfence against 32. The test therefore uses the measured host ratio, not the
  count-based projection in the triage brief ("fdiv about 2.27 h" at 3060 usteps/mcycle).
* The test does not drive the chain. It does not show the honest join reverting with `TournamentIsClosed` on
  testnet constants. A testnet child envelope is at most about 10.3 h (C = 8 h + 2G + T + 2G). On Dave's reference
  host with slack 2, the sfence leaf projects to about 24 h, so it would exceed that envelope. With no slack it
  projects to about 12 h.
* The test does not decide the severity reading. It is Critical under "worst-case cost ... larger than what the
  deployment was sized for". It is Medium if section 3's "only changes how long a claim may take to respond" covers
  clock sizing in the referee model. Whether a guest-kernel sfence loop, rather than a U-mode workload only, counts
  for a correctly designed application is also for the reviewer.
