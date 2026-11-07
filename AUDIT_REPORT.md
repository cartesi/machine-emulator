# PRT Audit Report

Status: **in progress** (round 1 review).

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

### Round 1

Nine hunters ran; they reported 23 raw candidates, one from a blocked run that was discarded (see below). Dedup
kept 20 of the 22 others. All 20 were proven, except R1-SOLIDITY-1, whose prover disproved it. Disproving review is
in progress.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R1-VERIFIER-1 | emulator | Critical | Uarch verifier aborts the process on a relayed log against a fabricated before-state | **Confirmed, Critical** | Reproduced by prover, reviewer and orchestrator; see `BUGS.md` |
| R1-VERIFIER-2 | emulator | Medium | Mcycle-level step verifier lets the log header choose the hash function | Duplicate | Same root cause as R1-HASH-1 (refuted) |
| R1-SOLIDITY-1 | machine-solidity-step | Critical | Honest input-delivery proof cannot fit per-transaction limits for large inputs | Disproved by prover | The input record (rollups-contracts `InputBox`, `INPUT_MAX_SIZE = 1 << 16`) caps inputs at 64 KiB; the worst reachable proof is 82,824 bytes, with a 3.3M-gas calldata floor, within every limit |
| R1-TRANSITIONS-1 | emulator | High | `collect_uarch_cycle_root_hashes` fast uarch reset restores only dirtied uarch-RAM words | **Confirmed, High** | Divergence from the verified reset, reachable only with a non-pristine uarch (invalid template); see `BUGS.md` |
| R1-ARCH-1 | emulator | Medium | CLINT `mtimecmp`-to-cycle conversion overflows, raising spurious timer interrupts | **Confirmed, Medium** | Deterministic, consistent across paths, no correct guest relies on it; see `BUGS.md` |
| R1-ARCH-2 | emulator | Medium | Misaligned SC.W/SC.D without a reservation returns failure instead of trapping | **Confirmed, Medium** | Deterministic, consistent across paths, no correct guest relies on it; the access-fault part of the claim is spec-permitted; see `BUGS.md` |
| R1-ARCH-3 | emulator | Medium | Page walk ignores PMA failures on PTE accesses (A/D updates to non-writable memory dropped) | **Confirmed, Medium** | Deterministic, consistent across paths, no correct guest places page tables outside RAM; see `BUGS.md` |
| R1-ARCH-4 | emulator | Medium | `sip` writes let S-mode set or clear STIP and SEIP | **Confirmed, Medium** | Deterministic, consistent across paths, affects only S-mode's own interrupts; see `BUGS.md` |
| R1-HASH-1 | emulator | Medium | Step-log replay verifier lets the proof select the hash function | Refuted by reviewer | `machine::verify_step` serves no transition form; it is the documented sha256 step log for ZK proving (out of scope), and the form verifiers hard-code keccak256 |
| R1-GUESTTOOLS-1 | prt-player-bridge | Critical | Honest player aborts when a guest yield's data exceeds the tx buffer | **Confirmed, Critical** | Reachable with a correctly designed application (DATA is ignored on reject); see `BUGS.md` |
| R1-GUESTTOOLS-2 | prt-player-bridge | Critical | Honest player asserts the guest's outputs Merkle root matches its own frontier | Refuted by reviewer | The assert fires only when the guest's root disagrees with its own accepted outputs, which a correctly designed application never does; a subverted guest already controls everything the canonical state commits to |
| R1-GUESTTOOLS-3 | machine-guest-tools | Medium | `rollup voucher` accepts values shorter than 32 bytes | Refuted by reviewer | Triggered only when the application violates the CLI's documented 32-byte value format (not correctly designed); no rule violated, the emulator stays deterministic |
| R1-PLAYER-1 | prt-player-bridge | Critical | Relaunched honest bridge abandons its claim when an adversary joined that commitment first | **Confirmed, Critical** | Section 7 adversary plus any relaunch after the joining window; see `BUGS.md` |
| R1-PLAYER-2 | prt-player-bridge | Critical | 8-entry input-boundary cache makes reaching a chosen position cost about n/5 whole inputs | **Confirmed, Critical** | Reach cost grows linearly with the adversary-chosen input count; see `BUGS.md` |
| R1-PLAYER-3 | prt-player-bridge | Critical | `get_seal` issues one unpaged `eth_getLogs` from deployment to tip | **Confirmed, Critical** | Deterministic once the chain outgrows a standard node range limit; see `BUGS.md` |
| R1-PLAYER-4 | prt-player-bridge | High | Epoch listener fetches and retains every InputBox log of every application | **Confirmed, High** | Unbounded cost from relayed data the operator may decline (indexed topic not filtered); see `BUGS.md` |
| R1-PLAYER-5 | prt-player-bridge | High | Next-epoch inputs run before the current dispute ticks, so an input flood delays it | **Confirmed, Critical** | Reviewer raised the claimed High to Critical: A7-sized clocks do not budget next-epoch batches; see `BUGS.md` |
| R1-REFEREE-1 | prt-referee-model | Critical | Late Sybil re-post of the honest claim sets its clock to one block | **Confirmed, Critical** | Section 7 Sybil plus admission-ordered clock assignment; see `BUGS.md` |
| R1-REFEREE-2 | prt-referee-model | Critical | Output proofs are not range-checked: each output is accepted again at index i - 2^63 | **Confirmed, Critical** | Any public output proof is re-accepted with bit 63 set; see `BUGS.md` |
| R1-ROBUST-1 | prt-player-bridge | Critical | Honest player keeps every tx-output payload of an input in memory | **Confirmed, Critical** | Guest-driven unbounded host allocation on the mandatory path (R8 fails, so the subverted-guest exclusion does not apply); see `BUGS.md` |
| R1-ROBUST-2 | prt-player-bridge | Critical | Honest player crashes on a manual yield whose length field exceeds the tx buffer | Duplicate | Same root cause as R1-GUESTTOOLS-1 |
| R1-ROBUST-3 | prt-player-bridge | High | Each guest automatic yield costs the honest player a JSON-RPC round trip | Proven, in review | |

## Blocked agents

- `hunt:HASH`, round 1: the hunter on the session model set `blocked_by_safeguards` but still returned one candidate:
  "the referee model accepts an output proof at an index outside the outputs tree". The workflow treated the run as
  blocked and retried it on `sonnet`, which completed and produced R1-HASH-1. The dropped candidate is the same defect
  as R1-REFEREE-2, so it is covered.

No reviewer has been blocked so far.

## Left uncovered

Filled in at the end of the audit.

## Gaps in the threat model

Collected as the audit runs; final at the end.

- **Input size versus chain limits.** The proof of an advance-state delivery grows linearly with the input. The
  receive buffer holds 2 MiB, but deliveries above roughly 400 KB yield proofs that cannot fit an Ethereum
  transaction. Today the only bound is `INPUT_MAX_SIZE = 1 << 16` in the rollups contracts' `InputBox`, which
  section 5 does not list as an obligation (from R1-SOLIDITY-1). A3 or A7 could require the input record to cap
  inputs at a size whose honest delivery proof fits the chain's per-transaction limits.
- **Crash-safety of the referee itself.** Section 4 requires paths that carry relayed data to report errors without
  terminating the process, and section 8 rates the referee model as a deployed referee. The model does not say
  explicitly that one shared referee process failing on one match's data must not stop the other matches
  (R1-VERIFIER-1).
