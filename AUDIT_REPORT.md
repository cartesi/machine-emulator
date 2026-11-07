# PRT Audit Report

Status: **extra rounds in progress** (round 8 confirmed two new issues, so the clean-round count restarted again; round 9 next). The headline block below is the rounds 1-3 snapshot; it is rewritten when the extra rounds finish.

**Running extra-rounds total:** round 4 (variant analysis) confirmed 6 new issues, bringing the confirmed total to **30 (14 Critical, 8 High, 8 Medium)**. See the round 4 candidate table and the Extra rounds section.

**Result: 24 confirmed issues (12 Critical, 6 High, 6 Medium), listed in `BUGS.md`; 5 candidates rejected and 3
merged as duplicates.** All 24 tests under `bugs/` fail deterministically on `feature/prt-audit`. A final pass ran every
one of them and each exited with status 1, the bug present, and none with a harness error.

| Component | Critical | High | Medium |
|---|---|---|---|
| PRT player and bridge (honest operator) | 8 | 3 | 0 |
| PRT referee model | 3 | 0 | 1 |
| Emulator | 1 | 1 | 5 |
| `machine-solidity-step` (with the emulator for R2-SOLIDITY-1) | 0 | 2 | 0 |
| `machine-guest-tools` | 0 | 0 | 0 |

The emulator's Critical, R1-VERIFIER-1, is also what kills the referee model. The honest operator holds most of the
Criticals, and none of them needs an emulator defect: crashes on guest or relayed data, restarts, scheduling, and
costs that grow with the adversary's inputs or the application's age. No soundness failure was found in the
emulator's transition function or its verifiers at reachable states. Every verifier divergence found occurs only at
unreachable before-states (High), or accepts trailing data without effect on the result (Medium).

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

### Round 2 angles

The same nine angles. Each hunter received every earlier candidate with its outcome, the areas its round-1 hunter
reported as uncovered (as priorities), and calibration notes from the round-1 refutations:

- the mcycle-level `verify_step` and sha256 step logs serve ZK proving, which is out of scope;
- subverted guest software is excluded while R7 and R8 hold, but not when a guest action breaks R8;
- triggers that need an application that is not correctly designed are out of scope;
- average-case performance is out of scope, but worst-case cost is not.

### Round 3 angles

The final round. VERIFIER, SOLIDITY, ARCH, PLAYER, REFEREE and ROBUST continue, with the areas their round-2 hunters
reported as uncovered as priorities. TRANSITIONS, HASH and GUESTTOOLS were dropped after producing no new candidate in
round 2. The calibration notes add the round-2 refutation (reserved encodings are unspecified, so executing them in a
ratified way conforms), that unreachable-state defects are at most High, and that the Dave contracts are out of scope
and unavailable.

### Models used

- Rounds 1-4 agents ran on Claude Opus 5.5, taken from the session model. Fallbacks ran on `sonnet`:
  `hunt:HASH@sonnet` (round 1) and `hunt:TRANSITIONS@sonnet` (round 2).
- One exception: the prover of R4-VARRANGE-1 (round 4) ran on Claude Opus 4.8, after the session model changed
  mid-round. Its reviewer ran on Opus 5.5, and the orchestrator reproduced the test, so the verdict does not rest on it.
- From round 5, agents are pinned to the exact model ID `claude-opus-5-5` at High effort. A first launch of round 5
  used the alias `opus`, which resolved to Opus 4.8 on this setup; it was stopped after two hunters started and
  relaunched with the exact ID. No result from that launch was used.
- Safeguard fallbacks (`sonnet`, then `haiku`) remain, as `AUDIT.md` requires.

## Extra rounds

After the planned audit closed, extra rounds were run at the requester's request. Each one splits the work with a
different strategy, so that no single way of dividing the code decides what gets examined. They stop once two
consecutive rounds, each with a different strategy, confirm no new issue. Each round keeps the limits of `AUDIT.md`:
at most 6 hunters (10 from round 5 on, at the requester's request), at most 5 candidates each, one disproving reviewer per candidate, and a commit and push for every
confirmed issue. Hunters receive every earlier candidate with its outcome, and calibration notes from the
refutations.

| Round | Strategy | Angles |
|---|---|---|
| 4 | Variant analysis: one hunter per family of confirmed bugs, searching the whole scope for other sites with the same root-cause pattern | VARABORT (process-terminating errors on data that must be handled), VARCLOCK (clock and deadline arithmetic), VARRANGE (missing range and index checks), VARGROWTH (unbounded growth with volume or age), VARSTATE (derived, cached or restored state diverging), VARSPEC (architectural deviations in traps, CSRs, permissions) |
| 5 | Data flow: one hunter per untrusted source, followed end to end across components | planned |
| 6 | Lifecycle phase: one hunter per phase of an epoch and of the operator | planned, if needed |
| 7 | File partition: disjoint file sets, each against the whole threat model | FPINTERP, FPINTERP2, FPHOSTAPI, FPCLI, FPSOLIDITY, FPGUESTTOOLS, FPPRT, FPPRTREST, FPMACHINE, FPMEM, FPUARCH |
| 8 | Dynamic testing: run fuzzers, differential harnesses, crash and fault injection, sanitizer builds and a randomized simulation, and report only what an executed reproducer shows | DYNUARCHDIFF, DYNLOGFUZZ, DYNPERSIST, DYNHASHPROP, DYNAPIFUZZ, DYNGUESTTOOLS, DYNPRTSIM, DYNCLAIMCMP, DYNSOLEXEC, DYNPLAYERFAULT |
| 9 | Attack-goal driven: start from each way to break a section 1 goal and search for any path that reaches it | planned |

## Candidates

### Round 1

Nine hunters ran; they reported 23 raw candidates, one from a blocked run that was discarded (see below). Dedup
kept 20 of the 22 others. The provers proved 19 and disproved R1-SOLIDITY-1. One disproving reviewer per proven
candidate reached a verdict, so no second reviewer was needed: 16 confirmed (9 Critical, 3 High, 4 Medium) and 3
refuted. The round ran 50 agents, all on the session model except `hunt:HASH@sonnet`. Every angle produced a new
candidate, so none was dropped. A container restart interrupted the run once, and it resumed from its journal: only
two in-flight provers ran again.

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
| R1-ROBUST-3 | prt-player-bridge | High | Each guest automatic yield costs the honest player a JSON-RPC round trip | **Confirmed, High** | Constant factor of about 5-10x over the existing worst case (magnitude corrected by the reviewer); see `BUGS.md` |

### Round 2

Nine hunters ran. The TRANSITIONS hunter on the session model reported a safeguard block with no candidates and was
retried on `sonnet`, which found none. TRANSITIONS, HASH and GUESTTOOLS produced no new candidate and are dropped from
round 3. The other six hunters reported 8 candidates, and dedup kept 7. All 7 were proven, and one disproving
reviewer per candidate reached a verdict: 6 confirmed (2 Critical, 3 High, 1 Medium) and 1 refuted. The round ran 25
agents, all on the session model except `hunt:TRANSITIONS@sonnet`. A second container restart interrupted the round
during hunting; it resumed from its journal, and only the two in-flight hunters ran again.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R2-VERIFIER-1 | emulator | High | Uarch step verifiers accept ECALL `write_tlb` with out-of-range set or slot indices | Duplicate | Same root cause as R2-SOLIDITY-1 |
| R2-VERIFIER-2 | emulator | Medium | Send-cmio-response verifier accepts read accesses carrying unchecked `written`/`written_hash` fields | **Confirmed, Medium** | Trailing log data accepted without effect on the after-hash; see `BUGS.md` |
| R2-SOLIDITY-1 | machine-solidity-step | High | TLB-write ECALL indices are unchecked in both uarch verifiers | **Confirmed, High** | Only at unreachable before-states (indices fixed by the pristine uarch); Solidity part traced, not executed; see `BUGS.md` |
| R2-SOLIDITY-2 | machine-solidity-step | High | `Memory.validateStrideLength` off-by-one rejects every access to the last leaf | **Confirmed, High** | Completeness divergence only at unreachable states (top page is never mapped); modeled, not executed on-chain; see `BUGS.md` |
| R2-ARCH-1 | emulator | Medium | Reserved RV64C encodings are executed as Zcb instructions | Refuted by reviewer | Reserved encodings are UNSPECIFIED in the RISC-V spec, so executing ratified Zcb is conforming and documented (`CHANGELOG.md`); no correct guest relies on a trap |
| R2-PLAYER-1 | prt-player-bridge | Critical | Older epochs' bridges cancel or replace the current epoch's pending transactions | **Confirmed, Critical** | Reached on the honest path on any chain without automine; see `BUGS.md` |
| R2-REFEREE-1 | prt-referee-model | Critical | Sealed uarch leaf gives the honest claim only the opponent's remaining clock to prove | **Confirmed, Critical** | Model disagrees with Dave's leaf-race timeout rule, on the unsafe side; see `BUGS.md` |
| R2-ROBUST-1 | prt-player-bridge | High | Every past epoch's dispute bridge keeps re-observing and retaining the full log history | **Confirmed, High** | Unbounded growth with age from data the operator may decline; see `BUGS.md` |

### Round 3

The final round ran six hunters. SOLIDITY, VERIFIER, ARCH and ROBUST found no new candidate. PLAYER and REFEREE
reported one each, and dedup kept both. Both were proven and confirmed by one reviewer each (1 Critical, 1 Medium).
The round ran 11 agents, all on the session model, and no agent was blocked. Hunting then stopped, as `AUDIT.md`
bounds it to 3 rounds, with no open candidate left.

### Totals

| Round | Agents | Raw candidates | Distinct | Confirmed | Rejected |
|---|---|---|---|---|---|
| 1 | 50 | 23 (one discarded with a blocked run) | 20 | 16 | 4 |
| 2 | 25 | 8 | 7 | 6 | 1 |
| 3 | 11 | 2 | 2 | 2 | 0 |
| All | 86 | 33 | 29 | 24 | 5 |

Every prover and reviewer ran on the session model, Opus 5.5. No issue in `BUGS.md` was confirmed only by a fallback
model, and none is reported without a proof of concept. Two issues, R2-SOLIDITY-1 (its Solidity half) and
R2-SOLIDITY-2, are proven against a model of the pinned Solidity source rather than on-chain, and `BUGS.md` says so.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R3-PLAYER-1 | prt-player-bridge | Critical | Honest player cannot sign a `winLeafMatch` proof for inputs of about 36 KB or more (calldata passed to `cast` as a shell argument) | **Confirmed, Critical** | A 37 KB input forces a leaf whose honest proof cannot be signed; see `BUGS.md` |
| R3-REFEREE-1 | prt-referee-model | Medium | Referee narration raises on adversary-chosen data inside the referee coroutine | **Confirmed, Medium** | Liveness and output availability lost on demand, goal unaffected; see `BUGS.md` |

### Round 4 (extra: variant analysis)

Six hunters ran, one per family of confirmed bugs. VARCLOCK found no new candidate. The other five reported 6
candidates, and dedup kept all of them. All 6 were proven and confirmed by one reviewer each (2 Critical, 2 High, 2 Medium). A safety classifier repeatedly stopped the orchestrator's detailed write-up of R4-VARRANGE-1 (a libcmt missing-bounds-check finding the reviewer confirmed Critical and the orchestrator reproduced); `BUGS.md` carries a factual summary and the committed test instead.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R4-VARABORT-1 | emulator | Critical | `cartesi-machine` CLI cannot compute claims when a rejected input leaves DATA above the transmit buffer | **Confirmed, Critical** | Same API throw as R1-GUESTTOOLS-1, but in the CLI, with its own fix; see `BUGS.md` |
| R4-VARRANGE-1 | machine-guest-tools | Critical | libcmt ABI decoder accepts wrapping dynamic offsets, so an app commits an output built from the wrong bytes | **Confirmed, Critical** | Reviewer-confirmed and orchestrator-reproduced; a safety classifier stopped the detailed write-up, so the record is a factual summary plus the committed test |
| R4-VARGROWTH-1 | prt-player-bridge | Critical | Stored player keeps every epoch's directory and checkpoint forever | **Confirmed, High** | Reviewer lowered the claimed Critical: per-epoch use is bounded and settled epochs can be pruned by hand; see `BUGS.md` |
| R4-VARSTATE-1 | prt-player-bridge | High | Relaunched player keeps its stored epoch after the confirmed input history or the seal changed | **Confirmed, High** | Relaunch removes the fail-closed margin after a reorg beyond the input policy; see `BUGS.md` |
| R4-VARSPEC-1 | emulator | Medium | Page walk accepts non-leaf PTEs with the reserved A, D or U bits set | **Confirmed, Medium** | Deterministic, consistent across paths, no correct guest sets these bits; see `BUGS.md` |
| R4-VARSPEC-2 | emulator | Medium | Interrupts change `instret` | **Confirmed, Medium** | Deterministic, consistent across paths, contradicts the manual's counter definition; see `BUGS.md` |

### Round 5 (extra: data flow)

Six hunters ran, one per untrusted source. DFCHAIN, DFCLAIMPROOF, DFPEER and DFLOADED found no new candidate. DFINPUT
and DFGUESTOUT reported 3 candidates, and dedup kept all of them. All 3 were proven and confirmed by one reviewer each
(3 Critical). The round ran 13 agents. Agents ran on Claude Opus 5.5 (exact ID) at High
effort.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R5-DFINPUT-1 | machine-guest-tools | Critical | libcmt `cmt_abi_get_bool` returns success for words that are not a valid bool | **Confirmed, Critical** | Reviewer-confirmed and orchestrator-reproduced; see `BUGS.md` |
| R5-DFGUESTOUT-1 | prt-player-bridge, emulator | Critical | Player and CLI use the guest's `tohost` DATA as the length when reading the outputs root | **Confirmed, Critical** | Reachable for valid templates that yield accepted with DATA other than 32 (the manual contradicts itself on this); see `BUGS.md` |
| R5-DFGUESTOUT-2 | emulator | Critical | CLI keeps every tx-output payload in memory and writes each report or rejected output to its own file | **Confirmed, Critical** | CLI counterpart of R1-ROBUST-1 with its own location and fix; see `BUGS.md` |

### Round 6 (extra: lifecycle phase)

Eight hunters ran, one per phase: setup, open epoch, sealing, mcycle dispute, uarch dispute, settlement, restart and
epoch hand-off. Only LCSETUP found candidates (2). The other seven found none. No agent was blocked. Both candidates
were proven and then refuted by their reviewers, so **round 6 confirmed no new issue: the first clean round**. Agents ran on
Claude Opus 5.5 (exact ID) at High effort.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R6-LCSETUP-1 | prt-player-bridge | High | A reopened epoch directory is not bound to the checkpoint or template it continues | Refuted by reviewer | Reproduced, but the `--state` directory is the operator's own trusted state, and feeding it another deployment's epoch directory is an operator configuration error outside the section 7 adversary. R13's version mismatch concerns the build against the deployment, which agree here. The reopened machine is not the valid template of the deployment being defended. At most an informational hardening note |
| R6-LCSETUP-2 | prt-player-bridge | High | Player computes with the checkpoint manifest's sampling period and never compares it with the factory geometry | Refuted by reviewer | Reproduced, but it requires the trusted operator to misconfigure its own node: the documented path takes the geometry from the factory. The node never posts a claim built with the wrong period, so it does detect the mismatch, only late and with a bare assert. R13 concerns the build against the deployment, which agree. At most a hardening note: assert the manifest's period against the factory's geometry at startup |

### Round 7 (extra: file partition)

Eleven hunters ran, each on a disjoint set of files, reading every function against the whole threat model. Of the 4 candidates, 2 were confirmed (1 Critical, 1 Medium), so **round 7 was not clean**. The prover disproved 1, and the orchestrator did not confirm 1 after the reviewer had. FPINTERP1,
FPINTERP2, FPHOSTAPI, FPCLI, FPSOLIDITY, FPGUESTTOOLS and FPPRT found no new candidate. FPMACHINE, FPMEM, FPUARCH and
FPPRTREST reported 4 candidates, and dedup kept all of them. No agent was blocked. Agents ran on Claude Opus 5.5
(exact ID) at High effort.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R7-FPUARCH-1 | emulator | Critical | An interrupted mark-dirty leaves a dirty page under clean ancestors in a shared stored machine, so the root hash goes stale after a reload | **Confirmed, Critical** | Reviewer kept Critical; narrow crash window simulated with gdb and SIGKILL; see `BUGS.md` |
| R7-FPMACHINE-1 | prt-player-bridge | High | The honest player runs every machine with the default line-flushed stdout console | Disproved by prover | The mechanism is real, but it raises the average cost only: a guest's `sfence.vma` already costs more per mcycle (about 0.9 µs against 0.17 to 0.7 µs), so the worst-case cost of no unit of work changes (R12). A lead the prover did not pursue is recorded under "Left uncovered" |
| R7-FPMEM-1 | emulator | Medium | A PLIC claim/complete write clears the software-written `mip.SEIP` bit | **Confirmed, Medium** | Deterministic, consistent across paths, no correct guest relies on it; see `BUGS.md` |
| R7-FPPRTREST-1 | prt-player-bridge | Critical | The honest bridge inflates gas by 20% with no per-transaction cap, so a proof that fits the 2^24 gas cap can be signed above it | Not confirmed (orchestrator override of the reviewer's Critical) | The reviewer confirmed it and reproduced it, but only with 350 KB and 660 KB input payloads. The `InputBox` this branch deploys against (rollups-contracts v3.0.0-alpha.10, also v2.1.1) reverts above `INPUT_MAX_SIZE = 1 << 16`, which I verified directly. The largest honest delivery witness is then about 94 KB, with an estimate near 3.8M gas and 1.2 times that near 4.6M, far below 2^24 = 16.8M. The inflation cannot push a real proof over the cap. This is the same reasoning as for R1-SOLIDITY-1. It becomes real only if `INPUT_MAX_SIZE` is raised above roughly 300 KB or another input source is used. Hardening note: clamp the signed gas at the per-transaction cap, and give the bridge's assertions messages. R3-PLAYER-1, whose trigger is 36 KB, is unaffected. The test directory is left untracked |

### Round 8 (extra: dynamic testing)

Ten hunters ran, each building and running its own harness (differential and mutation fuzzers, crash injection with
`gdb` and an `LD_PRELOAD` store-fault injector, ASan and UBSan builds, a randomized referee simulation, fault injection
into the bridge, and the Solidity verifiers on a real EVM). Of the 4 candidates, 2 were confirmed (1 Critical,
1 Medium), so **round 8 was not clean**. The provers proved all 4; the disproving reviewers refuted 2. Eight hunters
found no candidate; each of them reports what it ran in the "Round 8 coverage" list below. Agents ran on Claude Opus 5.5
(exact ID) at High effort, except the two re-runs of blocked hunts (see Blocked agents).

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R8-DYNPLAYERFAULT-1 | prt-player-bridge | Critical | The honest bridge's signer wedges for good when its journal holds a candidate the node does not have, signed near the fee or tip ceiling, and that candidate's job is no longer due | **Confirmed, Critical** | Reproduced by prover, reviewer and orchestrator; the honest claim sends no move for the rest of the epoch; see `BUGS.md` |
| R8-DYNPERSIST-1 | emulator | Medium | `write_memory`, `write_word` and `fill_memory` store the data before marking the page dirty, so an interrupted call leaves a stale hash tree in a shared stored machine | **Confirmed, Medium** | Reproduced by prover, reviewer and orchestrator; found only by the fallback-model hunter; the stored player is protected by its revert snapshot, hence Medium; see `BUGS.md` |
| R8-DYNPRTSIM-1 | prt-referee-model | High | Any connection can take the unauthenticated phase-closer role, close admission before the honest player connects, or stop the referee | Refuted by reviewer | Reproduced, but the phase closer and its stop command are documented orchestration of one trusted referee process (`THREAT_MODEL.md` section 4 and 5, manual simplification), not a chain-facing role; a deployed referee has no admission phase |
| R8-DYNPRTSIM-2 | prt-referee-model | Medium | An abrupt disconnect by any connection raises in the transport reader and kills the referee process | Refuted by reviewer | Reproduced (16 of 150 random seeds), but the model's fail-fast transport is deliberate and pinned by its own tests, and the manual already concedes that a connected player can stall the demonstration |

Round 8 coverage (what each hunter ran; hunts with no candidate are not evidence of absence):

- **DYNUARCHDIFF** (re-run on `sonnet`): about 55k random-stream mcycles over about 300 seeds compared across native,
  1-mcycle chunks, `run_uarch` with reset, the step and reset log verifiers and `collect_*`; about 25k mcycles of cmio
  harness with 1.7k input deliveries; about 35k log and parameter mutations. No disagreement. No sanitizer build.
- **DYNLOGFUZZ**: 1574 honest logs mutated with 28 operators, about 131k iterations without sanitizers and about 1100 s
  under an out-of-tree ASan and UBSan build of `libcartesi`, plus 30k Lua-table mutations differentially against the
  JSON-RPC server, edge-state round trips and 4.3k forked step differentials. No crash, no wrong acceptance; the only
  aborts are R1-VERIFIER-1, and the only accepted mutants are R2-VERIFIER-2.
- **DYNPERSIST** (re-run on `sonnet` found R8-DYNPERSIST-1): several thousand kill points injected with an `LD_PRELOAD`
  store-fault injector across reopen, run, write, cmio and proof paths, a random-SIGKILL differential harness, a
  stored-player kill campaign and an ENOSPC store test. Every other mismatch was the R7-FPUARCH-1 family.
- **DYNHASHPROP**: five seeded differential harnesses for about 40 minutes (frontier forest against a naive reference,
  hash-tree and proof properties). No disagreement.
- **DYNAPIFUZZ**: ASan and UBSan build of the library, the Lua module and the JSON-RPC server; verifier-API and
  JSON-RPC body fuzzing. No memory error.
- **DYNGUESTTOOLS**: ASan and UBSan build of libcmt, the rollup CLI and a mock of the HTTP server, with a strict
  reference decoder for every width. Every deviation was R4-VARRANGE-1 or R5-DFINPUT-1.
- **DYNPRTSIM**: randomized adversarial referee simulation (1000 seeds clean with disconnects disabled; 150 seeds with
  them). Found the two refuted candidates above.
- **DYNCLAIMCMP**: the honest claim computed by a hand-rolled reference, the CLI and the forked, stored and reopened
  player on randomized bare-metal guests and one Linux guest. No disagreement. Its work was not safety-reviewed (see
  Blocked agents).
- **DYNSOLEXEC**: the pinned Solidity contracts compiled unchanged with solc-js 0.8.30 and executed on `revm`
  (Cancun): about 100k Solidity-versus-C++ checks and about 30k mutated proofs, including honest Linux states, 522
  TLB-write steps, send-cmio-response across lengths and reasons, and 16 transition proofs encoded by
  `prt-ethereum.transition_proof`. No new mismatch; the largest honest proof used 1.64M gas. It also executed
  R2-SOLIDITY-2 (the last-leaf revert). `MetaStep.sol` and the Dave consumers were not executed.
- **DYNPLAYERFAULT**: the real bridge tick and journal on an in-memory EIP-1559 node with injected RPC errors, mempool
  loss, reorgs and kills. Found R8-DYNPLAYERFAULT-1 (30 of 41 fee-spike seeds wedged; 180 or more seeds without fee
  spikes had no missed job).

## Blocked agents

- `hunt:HASH`, round 1: the hunter on the session model set `blocked_by_safeguards` but still returned one candidate:
  "the referee model accepts an output proof at an index outside the outputs tree". The workflow treated the run as
  blocked and retried it on `sonnet`, which completed and produced R1-HASH-1. The dropped candidate is the same defect
  as R1-REFEREE-2, so it is covered.

- `hunt:TRANSITIONS`, round 2: the hunter on the session model set `blocked_by_safeguards` and returned no
  candidate. Its retry on `sonnet` completed and found no new candidate.

- `hunt:DYNUARCHDIFF` and `hunt:DYNPERSIST`, round 8: the hunters on Opus 5.5 set `blocked_by_safeguards` (DYNPERSIST
  reported that a safety classifier stopped it while it was analyzing one anomalous crash image, seed 1031, which it
  asked to have examined independently). The workflow re-ran each on `sonnet`. The DYNUARCHDIFF re-run found no
  candidate. The DYNPERSIST re-run found R8-DYNPERSIST-1, a **fallback-only discovery**; its prover and reviewer ran on
  Opus 5.5. The seed-1031 image was not re-examined by the primary model; the sonnet campaign found only
  R7-FPUARCH-1-family mismatches.

- `hunt:DYNCLAIMCMP`, round 8: the workflow reported its work as unreviewed because an upstream safety filter refused
  the review request (which reacts to content in the subagent's own transcript, not to the work). The hunter returned
  no candidate and its output was checked for injection and instructions: it contained none. Treat its "no
  disagreement" as unreviewed evidence.

No prover or reviewer was blocked in any round, so no issue needed a fallback reviewer or was reported without a
proof of concept. The only fallbacks were the hunters above.

## Left uncovered

The hunt was bounded to 3 rounds (`AUDIT.md`). These areas were not examined, or were examined only partly. The
hunters reported them as uncovered and later rounds did not close them.

- **Solidity execution.** Foundry could not be installed in rounds 1 to 7 (refused by the sandbox's permission
  policy), so those findings rest on regeneration from the C++ (the generated `UArchStep.sol`, `UArchReset.sol` and
  `SendCmioResponse.sol` match token for token), line-by-line traces, and Lua models of the pinned source. In round 8
  a hunter obtained solc-js and `revm` from the package mirrors and executed the pinned contracts (see the Round 8
  coverage list), which executed R2-SOLIDITY-2; the orchestrator could not re-run that harness because its own install
  of the EVM was refused. R2-SOLIDITY-1's acceptance claim is still only modeled, `MetaStep.sol` was not executed, and
  the compiler flags of an actual deployment were not compared.
- **The Dave contracts.** They are out of scope and not in the tree. The parts of the encoding seam that they own were
  not checked: how they compute `dataHash` from input bytes, how they parse the input-length prefix that
  `transition_proof` emits, the `MetaStep` counter they pass, how they map a position to its form, and whole-transaction
  gas. Neither was the reliance of R2-REFEREE-1 and R1-REFEREE-1 on Dave's behavior. Both cite it through the bridge
  and its specification, which encode Dave's rules, not through the contracts themselves.
- **Uarch worst case.** The worst-case number of uarch cycles per mcycle against `UARCH_CYCLE_MAX` (R4, R12) was
  measured only for representative heavy mcycles: TLB flushes, traps, page walks, soft-float. It was estimated, not
  bounded analytically, and an interrupt taken together with a flushing instruction in the same mcycle was not
  measured.
- **Differential fuzzing.** Round 8 ran differential fuzzing of the native, uarch and verifier paths (see its coverage
  list). Still not covered: exhaustive soft-float checking against a reference implementation, a sanitizer build under
  the differential harness, most S and U-mode and paging code in random streams (they settle in trap loops), PLIC,
  virtio, flash drives and the DTB, and a full line-by-line review of every RV64C, F and D handler.
- **Long runs.** Native and uarch were not compared over a full Linux boot, and forking through the JSON-RPC server was
  not compared with an uninterrupted run (store and load were).
- **Persistence.** Rounds 7 and 8 exercised crash consistency of shared backing stores (R7-FPUARCH-1, R8-DYNPERSIST-1).
  Still not covered: kills inside the `.phtc` and shadow-state files, power-loss durability (`fsync` ordering),
  `ENOSPC` and `SIGBUS` on sparse shared stores, read-only directories, the uarch-claim and `prove_state_transition`
  paths under kill, the JSON-RPC server under kill, and the player's own Lua file writes.
- **Claim correctness on output-emitting guests.** The honest player's mcycle and uarch claims were compared with the
  CLI's computation hashes only for bare-metal guests that emit no outputs. An input deadline reached after 2^48 real
  mcycles was checked only through a saturated template near 2^64.
- **`machine-guest-tools` at run time.** `rollup-http-server` under real concurrency and timeouts, `echo-dapp`, and
  libcmt's Merkle tree near 2^63 leaves were read but not exercised. Round 2's GUESTTOOLS hunter found nothing new
  inside the tools themselves.
- **Operator plumbing.** `prt-websocket.lua` frame parsing, fee and nonce corner cases of `prt-transactions.lua` under
  reorgs, JSON-RPC per-request allocation for large relayed logs, and the CLI's rollup paths under adversarial inputs
  were read but not stress-tested.
- **Collect-path cost of TLB-flush-heavy guests.** The prover of R7-FPMACHINE-1 measured, on the honest forked player,
  `input_added` taking about 2.7 to 3.2 s on a flood of 800000 `sfence.vma` instructions against about 0.8 s for the
  replay of the same input. The extra cost in the collect path was not investigated. A worst-case-cost (R12) hunt of
  the collect and hash-collection paths, with such guests, remains open.
- **Gas ceiling in the bridge (hardening note from R7-FPPRTREST-1).** `prt-transactions.lua` inflates the estimated gas
  by 20% with no per-transaction cap, so a proof that fits the 2^24 gas cap could be signed above it. It is
  unreachable under the `InputBox` 64 KiB input cap, so it was not confirmed. Clamping the inflated gas to the cap
  would remove the dependency on that external limit.
- **A3 in the referee model.** Enforcing the input limit per epoch (more than 2^24 inputs) was not exercised. In the
  model, inputs come from the referee's own command line.
- **Out of scope by `AUDIT.md`.** ZK proving (`risc0/`), the Linux kernel (including the `/dev/cmio` driver), OpenSBI,
  and the Dave and Cartesi Rollups Node validators.

## Gaps in the threat model

- **Input size versus chain limits.** The proof of an advance-state delivery grows linearly with the input. The
  receive buffer holds 2 MiB, but deliveries above roughly 400 KB yield proofs that cannot fit an Ethereum
  transaction. Today the only bound is `INPUT_MAX_SIZE = 1 << 16` in the rollups contracts' `InputBox`, which
  section 5 does not list as an obligation (from R1-SOLIDITY-1). A3 or A7 could require the input record to cap
  inputs at a size whose honest delivery proof fits the chain's per-transaction limits.
- **Crash-safety of the referee itself.** Section 4 requires paths that carry relayed data to report errors without
  terminating the process, and section 8 rates the referee model as a deployed referee. The model does not say
  explicitly that one shared referee process failing on one match's data must not stop the other matches
  (R1-VERIFIER-1).
- **Liveness of output acceptance.** Section 1 and A5 constrain which outputs may be accepted, but nothing requires
  the referee to keep accepting every output that the settled state does commit to. R3-REFEREE-1 halts output
  acceptance on demand without breaking any stated rule except the manual's.
- **The honest operator's path stops at the emulator.** Section 2 lists obtaining the template, advancing, delivering,
  storing and reloading, computing claims and producing proofs. It does not list submitting transactions, observing
  the chain, or restarting the operator process. Five of the twelve Criticals live there:
  - R1-PLAYER-1: restart recovery;
  - R1-PLAYER-3: the node's log-range limit;
  - R1-PLAYER-5 and R2-PLAYER-1: scheduling across epochs and a shared account;
  - R3-PLAYER-1: OS argument limits when signing.

  These were rated Critical through R4 ("cannot respond in time"), but naming submission, observation and restart as
  part of the path would remove the ambiguity.
- **R12 has no unit for the operator's own bookkeeping.** Its units are emulator work: mcycles, uarch cycles,
  deliveries, resets, logs, claim parts. Costs that grow with the application's age or with other parties' chain
  activity have no stated bound: R1-PLAYER-4, R2-ROBUST-1, and the replay distance of R1-PLAYER-2. A7 sizes clocks for
  a bounded number of matches, not for an operator whose per-pass cost grows with every past epoch.
- **Concurrent epochs.** The model treats each epoch's dispute alone. It does not say that the honest operator must
  defend overlapping epochs, or that A7 must cover accumulating epoch N+1 while disputing epoch N (R1-PLAYER-5,
  R2-PLAYER-1).
- **Which clock rule is normative.** Section 5 makes the manual's tournament normative except for its listed
  simplifications and its clock values. The manual states, as a rule, that no timeout win exists at a sealed leaf,
  while Dave and the bridge's own specification grant one (R2-REFEREE-1). The threat model gives no test for which
  side is defective, beyond rating by effect. Requiring the normative model itself to satisfy A7, so that the honest
  claim always plays on its own clock, would decide such cases.
- **Build configuration of off-chain verifiers.** R1 forbids compiler or optimization settings from changing any
  transition, but it speaks of reproducible machines on their states. The off-chain verifier's behavior on fabricated
  before-states depends on the build type: `relwithdebinfo` aborts, while `release` silently aligns the address
  (R1-VERIFIER-1). R10 could state that verifier outcomes, including rejection, must not depend on build
  configuration.
