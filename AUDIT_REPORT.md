# PRT Audit Report

Status: **in progress** (round 1 hunting).

This report follows the plan in `AUDIT.md` and the definitions of `THREAT_MODEL.md`. Confirmed issues are in
`BUGS.md`, and their tests are under `bugs/`.

## Setup

- Branch audited: `feature/prt-audit` at `b2f862a` (docs: prepare PRT audit).
- Pinned external components, fetched at their tags:
  - `machine-solidity-step` `v0.17.0-test1` (`6f91eb9b`).
  - `machine-guest-tools` `v0.18.0` (`5222250c`).
- Emulator built in-tree (`make`). The uarch program was built with the pinned cross toolchain of the emulator's
  `Dockerfile` (`g++-14-riscv64-linux-gnu=14.2.0-19cross1`, `gcc-riscv64-unknown-elf=14.2.0+19`, Debian
  `trixie-20250811`). Its pristine state hash, `0x558f38f2350970a0a566b2450afa64250059c1cff66c9a55560e5b93fa783926`,
  matches `UARCH_PRISTINE_STATE_HASH` in `machine-solidity-step` `v0.17.0-test1`, so the pinned uarch is
  reproducible from the audited source (R13).
- Guest images from `dependencies.lock`: Linux `v6.18.56-ctsi-1` and the `machine-guest-tools` `v0.18.0`
  `rootfs-tools.ext2`.
- Tests: `bugs/run.sh <ID>` runs `bugs/<ID>/test.lua` (or `test.sh`) with the environment of `bugs/env.sh`. Each
  test asserts the behavior the threat model requires, so it exits nonzero on `feature/prt-audit` while the bug is
  present and zero once it is fixed.

### Environment limitations

- No Solidity toolchain. Installing Foundry was refused by the sandbox's permission policy (both the installer
  script and the prebuilt release tarball), and no `solc` or EVM is otherwise available. Findings in
  `machine-solidity-step` are therefore demonstrated by differential tests against the C++ reference plus a trace of
  the Solidity code, and are flagged in `BUGS.md` as not executed on-chain.

## Process

A workflow runs each round: one hunter per angle (at most 6 at a time, at most 5 candidates each, reasoning before
proposing), a deduplication pass across hunters and earlier rounds, then for each distinct candidate a prover that
writes a deterministic failing test under `bugs/<ID>/`, and one independent disproving reviewer (a second one only
when the first is inconclusive). An agent blocked by safeguards is retried with a less capable model (`sonnet`, then
`haiku`). Hunting stops after 3 rounds, and an angle is dropped after a round with no new candidate.

Models: every agent runs on the session model (Opus 5.5) unless a fallback is recorded below.

### Round 1 angles

| Angle | Focus | Rules |
|---|---|---|
| VERIFIER | C++ log producers and verifiers on adversarial logs | R3, R10, R11, R2, R12, section 4 |
| SOLIDITY | `machine-solidity-step` versus the C++ reference | R3, R10, R11, R2, R13, R12 |
| TRANSITIONS | Cross-path agreement at grid boundaries, delivery, revert, deadlines, persistence | R2, R4, R5, R6 |
| ARCH | Faithful architecture, containment, determinism | R7, R8, R1, R14 |
| HASH | Hash-tree and computation-hash integrity | R9, R13, R2, R11 |
| GUESTTOOLS | `machine-guest-tools` rollup interface | Section 2 (correctly designed application), R7, A5 |
| PLAYER | PRT player and bridge (honest operator) | R4, R6, R12, A7, section 4, section 7 |
| REFEREE | PRT referee model, as if deployed | A1-A7, R3, R11 |
| ROBUST | Relayed-data robustness and bounded cost across host APIs | Section 4, section 8, R12, R8 |

## Candidates

Filled in as rounds complete.

## Blocked reviewers

None so far.

## Left uncovered

Filled in at the end of the audit.

## Gaps in the threat model

Filled in at the end of the audit.
