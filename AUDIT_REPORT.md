# PRT Audit Report

Status: **complete**. The audit stopped under the requester's rule, two consecutive rounds with different strategies that
confirm no new issue: round 17 (assert and error inventory of the honest operator, file by file) and round 18 (blind
invariant audit by subsystem) were both clean, after 18 rounds.

**Result: 55 confirmed issues (27 Critical, 13 High, 15 Medium), listed in `BUGS.md`.** 24 further candidates remain
rejected, each with its reason in the round tables. Every confirmed issue has a deterministic failing test under `bugs/`. A final pass ran all 55 of them with
`bugs/run.sh <ID>` on `feature/prt-audit`: each exited with status 1 (the bug present), and none with 0 or with a harness error (2).

| Component | Critical | High | Medium |
|---|---|---|---|
| PRT player and bridge (honest operator) | 14 | 8 | 0 |
| PRT referee model | 3 | 0 | 1 |
| Emulator | 8 | 3 | 14 |
| `machine-solidity-step` (with the emulator for R2-SOLIDITY-1) | 0 | 2 | 0 |
| `machine-guest-tools` | 2 | 0 | 0 |

Most of the Criticals are in the honest operator and need no emulator defect: crashes on guest or relayed data,
restarts, scheduling, fees, and costs that grow with the adversary's inputs or the application's age. The emulator's
Criticals fall in three groups: a verifier that aborts the process on a relayed log (R1-VERIFIER-1), CLI
claim computation that dies on guest data (R4-VARABORT-1, R5-DFGUESTOUT-2), and **stored machines that trust
files outside the hashed state when they load** (R7-FPUARCH-1 and the cache files R10-MANCLI1-1, R11-FAMCACHE-1,
R12-SECCACHE2-1 and -2), which the threat model forbids for a template that meets the valid-template conditions.
No soundness failure was found in the transition function itself or in the verifiers at reachable states: every
verifier divergence found occurs only at unreachable before-states (High), or accepts trailing data without effect
on the result (Medium). Two guest-tools decoders accept malformed input (R4-VARRANGE-1, R5-DFINPUT-1).

How the audit should be read:

- **Not blind, then blind.** Rounds 1-12, 15-17 told the hunters about earlier findings. Rounds 13, 14 and 18 withheld them.
  In those three rounds, blind hunters re-found 14, 14 and 29 earlier findings respectively (dedup merged 17 of 24,
  18 of 20 and 29 of 30 raw candidates, into 14, 14 and 16 distinct earlier findings), which is evidence that the audit has covered what hunters reach from the
  prompts used; it is not evidence that nothing remains.
- **A calibration error was found and corrected late.** From round 5 to round 14 the prompts told hunters that a defect
  needing an application that is not correctly designed was not a bug. Round 15's second opinion showed that the text
  of `THREAT_MODEL.md` scopes that exclusion to the emulator, so honest-operator failures on guest-written data are in
  scope (R4 at every reachable state). That overturned one refutation (R1-GUESTTOOLS-2) and rounds 16 and 17 swept the
  class (R16-RGOUTPUT-1, R16-RGBRIDGE-2). Rounds 5 to 14 may have under-reported this class in components other than
  the ones swept later; round 17 re-inventoried the whole honest operator under the corrected reading and found nothing.
- **Fallback models.** Hunts that a safeguard stopped were re-run on `sonnet`; three confirmed issues were found only
  that way (R8-DYNPERSIST-1, R12-SECCACHE2-1 and -2), and the proof of concept of one (R11-FAMFEES-1) was written by it.
  Their provers or reviewers ran on Opus 5.5 and the orchestrator reproduced every test. `BUGS.md` flags them.
- **Solidity.** A round 8 hunter executed the pinned contracts (solc-js and `revm`). It executed R2-SOLIDITY-2; the
  orchestrator could not re-run that harness. R2-SOLIDITY-1's acceptance claim is still only modeled.

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

- No Foundry. Installing it was refused by the sandbox's permission policy (both the installer script and the
  prebuilt release tarball). The orchestrator's later attempt to install an EVM (`pip install pyrevm`) was refused too.
  Findings in `machine-solidity-step` were therefore demonstrated by differential tests against the C++ reference plus a
  trace of the Solidity code, and flagged in `BUGS.md` as not executed on-chain, until a round 8 hunter obtained solc-js
  and `revm` from the package mirrors and executed the pinned contracts (see the Round 8 coverage list).
- The Dave contracts are not available (out of scope), and neither are `anvil`, `cast` or `forge`. The bridge and the
  referee model were exercised against mock chains and the pinned Dave sources that an agent compiled for its own harness.
- The machine has 4 shared CPUs and, at one point, ran short of disk (finished scratch harnesses were removed).

## Process

A workflow runs each round: one hunter per angle (at most 6 at a time in rounds 1-4 and at most 10 afterwards, at most
5 candidates each, reasoning before proposing), a deduplication pass across hunters and earlier rounds, then for each
distinct candidate a prover that writes a deterministic failing test under `bugs/<ID>/`, and one independent disproving
reviewer (a second one only when the first is inconclusive). An agent blocked by safeguards is retried with a less
capable model (`sonnet`, then `haiku`). `AUDIT.md` bounds the hunt to 3 rounds; the requester then asked for extra rounds
with different strategies until two consecutive rounds confirm no new issue (see Extra rounds).

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
- Safeguard fallbacks (`sonnet`, then `haiku`) remain, as `AUDIT.md` requires. Fallback runs after round 4 are listed under
  Blocked agents (`hunt:DYNUARCHDIFF`, `hunt:DYNPERSIST`, `hunt:SECCACHE2`, `hunt:RGUARCH`, `hunt:INVMODEL`,
  `prove:R11-FAMFEES-1`).
- Round 15 and the second-opinion reviewers ran on the exact ID `claude-opus-5-5` at High effort.
- The orchestrator (this session) switched between Opus 5.5 and Sonnet 5.5 during the audit; the git commits after
  round 7 carry a Sonnet 5.5 trailer for that reason.

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
| 9 | Attack-goal driven: start from each way to break a section 1 goal or a rule and search backwards, across components, for any path that reaches it | GOALACCEPT, GOALNODE, GOALWRONGCLAIM, GOALNOPROOF, GOALTIMEOUT, GOALOUTPUT, GOALDIVERGE, GOALNONDET, GOALESCAPE, GOALRESTORE |
| 10 | Manual and promise checking: each normative statement of the manual and each documented invariant in the code is checked against the implementation | MANCLI1, MANCLI2, MANLUA1, MANLUA2, MANGUEST, MANARCH, MANSTATE, MANCOMP, MANPRT, PROMISES |
| 11 | Family expansion of the late findings: each hunter enumerates every site of one bug shape found in rounds 7-10 | FAMPERSISTA, FAMPERSISTB, FAMCACHE, FAMMASK, FAMWEDGE, FAMFEES, FAMSPEC, FAMOPERATORIO, FAMUARCH |
| 12 | Second-order family expansion: the new shapes of round 11 (a register read from a constant on one path and from the shadow on another, decisions made at one chain state and executed at another) and the neighbors round 11 opened | SECSHADOW, SECPENDING, SECGAS, SECPERUNIT, SECCACHE2, SECLOCALREMOTE, SECEVMSEAM, SECCONFIG |
| 13 | Blind adversary personas: hunters play one persona each and are NOT shown the list of earlier findings (it goes only to dedup, whose duplicates measure the rediscovery rate) | ROLEINPUT, ROLECLAIMANT, ROLETEMPLATE, ROLEFAULT, ROLEVERSION, ROLECONTRACT, ROLESPEC, ROLECOST, ROLEAPPDEV, ROLELOCALAUDITOR |
| 14 | Blind invariant audit by subsystem: hunters again not shown the earlier findings; each owns one subsystem, derives its invariants from scratch and attacks them | INVINTERP, INVCSR, INVMMU, INVDEVICE, INVHASH, INVSTORE, INVLOGS, INVAPI, INVREFEREE, INVOPERATOR, INVGUEST |
| 15 | Second opinion on every refuted or disproved candidate (21): an independent reviewer re-reads each refutation against the text of `THREAT_MODEL.md` and `AUDIT.md` and may overturn it only by naming the step that contradicts them | R1-SOLIDITY-1, R1-HASH-1, R1-GUESTTOOLS-2/3, R2-ARCH-1, R6-LCSETUP-1/2, R7-FPMACHINE-1, R7-FPPRTREST-1, R8-DYNPRTSIM-1/2, R9-GOALACCEPT-1, R10-MANARCH-1/2, R12-SECPERUNIT-1, R13-ROLEVERSION-2, R13-ROLEAPPDEV-3/4, R13-ROLESPEC-4, R13-ROLECOST-3, R14-INVGUEST-3 |
| 16 | R4 at every reachable state: the corrected reading of the "application not correctly designed" exclusion applied to every honest-operator path that handles guest-written data | RGPLAYER, RGCLI, RGEMU, RGUARCH, RGOUTPUT, RGSTALL, RGBRIDGE |
| 17 | Assert and error inventory of the honest operator, file by file, under the corrected reading: every `assert`, `error`, unchecked access, unbounded loop and I/O call, and who controls each value | INVPRT1, INVPRT2, INVPRT3, INVPRT4, INVPLAYERMAIN, INVBRIDGE, INVTX, INVMODEL, INVCLISCRIPT |
| 18 | Blind invariant audit by subsystem, again under the corrected reading (hunters are not shown the earlier findings) | B18INTERP, B18CSR, B18MMU, B18DEVICE, B18HASH, B18STORE, B18LOGS, B18API, B18REFEREE, B18OPERATOR, B18GUEST |

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
| R1-GUESTTOOLS-2 | prt-player-bridge | Critical | Honest player asserts the guest's outputs Merkle root matches its own frontier | **Confirmed, Critical (overturned in round 15)** | Round 1's reviewer refuted it because the trigger needs an application that is not correctly designed. The round 15 second opinion overturned that: the section 8 exclusion is listed for the emulator and `AUDIT.md` keeps components it puts in scope (the honest operator) out of it, a valid template does not require a correctly designed application, and R4 holds at every reachable state; reproduced by the orchestrator; see `BUGS.md` |
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

### Round 9 (extra: attack-goal driven)

Ten hunters ran, each owning one way to break the section 1 goal or a rule and searching backwards from it through every
component. Of the 2 candidates, 1 was confirmed (Medium), so **round 9 was not clean**. The prover proved both and the
disproving reviewer refuted 1. Eight hunters found no candidate. All agents ran on Claude Opus 5.5 (exact ID) at High
effort; no hunt was stopped by a safeguard, so no fallback was used. Most hunters did not run a harness: the round
was a reading round, and its coverage lists below say what each did not reach.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R9-GOALRESTORE-1 | emulator | Medium | Mcycle hash collection defers the dirty marks of page-walk A/D writes to the end of each sampling period, so an interrupted collection leaves a shared stored machine with a stale hash tree | **Confirmed, Medium** | Reproduced by prover, reviewer and orchestrator; the stored player discards such directories, hence Medium; see `BUGS.md` |
| R9-GOALACCEPT-1 | prt-referee-model | Medium | The referee model accepts state-transition proofs that carry logs the transition form does not use | Refuted by reviewer | Reproduced, but the unused fields are never handed to any verifier and cannot change the form or the after-hash; every log a verifier receives is fully consumed (R3), the form follows only the position (R11, A2), and the model and the contracts differ only in wire encoding. At most an optional hardening: assert that the response carries exactly the logs of its form |

Round 9 coverage (hunts with no candidate are not evidence of absence):

- **GOALACCEPT**: every acceptance decision of the C++ uarch, reset and send-cmio replays and of the Solidity mirrors, the
  interrupt and fetch-cache points of native versus uarch, and the referee model's form selection. It ran one small
  experiment and no Solidity execution.
- **GOALNODE**: every site that produces or checks a Merkle proof in the referee model, `hash-tree.lua` and the
  verifiers (two-argument `keccak256` rejects non-32-byte inputs, so siblings cannot be re-split). Not fuzzed: the C++
  JSON access-log parser; not traced line by line: the forest proof producer.
- **GOALWRONGCLAIM**, **GOALNOPROOF**: the builders, bundle openers, fast and slow paths, rejection handling and
  the form selection against the contracts' conventions, by reading. No dynamic harness. Not examined: full
  native-versus-uarch instruction semantics, `prt-transactions.lua` and `prt-websocket.lua` beyond the angle, and the
  worst-case uarch cycles of an interrupt plus a flushing instruction (estimated at about 55k, not measured).
- **GOALTIMEOUT**: reported that a safety classifier stopped one of its responses; it reasoned from the first part of its
  review, ran no harness and no timing measurement. Not reviewed: most of `prt-websocket.lua`, the stored-player
  reopen paths (`prt.lua` 2245-2978) and the `prtu.lua` request and wait primitives. Treat its zero as partial.
- **GOALOUTPUT**: the output acceptance path end to end (A5 words authenticated at their height, HTIF masks, yield
  semantics). Not traced: the CLI's own output-proof generation.
- **GOALNONDET**: every host input into the transition (time, polling, console, runtime options, stop and resume,
  SIMD dispatch) and empirical checks of the page-hash-tree cache and dirty-page tree. Only the AVX-512 paths of this
  host were exercised; 16 KiB pages and 32-bit hosts were not.
- **GOALDIVERGE**: the places where native, uarch and verifiers differ by construction, including the build-flag split
  (asserts off in native, on in the uarch program). Random fuzzing covered MMU and paging lightly.
- **GOALESCAPE**: HTIF, console, hash-collection asserts, physical-address lookup and the shared-store paths.
  It reported that a safety classifier stopped one of its responses while it examined the virtio paths; it did not
  finish `virtio-address-range.cpp`, and did not look at p9fs, net, console devices, CLINT and PLIC in detail, the
  JSON-RPC server's use of guest data, or `dtb.cpp`. Those devices exist only in unreproducible machines. Treat its zero
  as partial.
- **GOALRESTORE**: found R9-GOALRESTORE-1 by reading the collection accessor. Not run: the full stored player under a
  kill during collection, and power-loss ordering.

### Round 10 (extra: manual and promise checking)

Ten hunters ran, each taking a disjoint slice of the manual (the command-line interface, the Lua interface, the guest
perspective, the system architecture, the hash views of state and outputs, the hash view of computation and the
verification game, the tournament) or the code's own comments, asserts and TODOs, and checking each normative
statement against the implementation. Five raw candidates were reported and dedup merged them into 4. Of those, 2 were
confirmed (1 Critical, 1 Medium), so **round 10 was not clean**. The prover disproved 2 and the disproving reviewer
confirmed the other 2. All agents ran on Claude Opus 5.5 (exact ID) at High effort; no hunt was blocked.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R10-MANCLI1-1 | emulator | Critical | Loading a stored machine trusts its page hash-tree cache (`hash_tree.phtc`, outside the hashed state), so a valid template with a poisoned cache reports the right root and then computes wrong hashes and proofs | **Confirmed, Critical** | Reproduced by prover, reviewer and orchestrator; rated by the explicit `THREAT_MODEL.md` section 8 clause on valid templates (if template distribution is wholly trusted, the residue is Medium); see `BUGS.md` |
| R10-MANLUA1-1 | emulator | Medium | The HTIF halt command ignores the `ihalt` availability mask | **Confirmed, Medium** | Reproduced by prover, reviewer and orchestrator; consistent across native, uarch and verifiers, contradicts the manual; see `BUGS.md`. Reported twice (R10-MANARCH-3 merged by dedup) |
| R10-MANARCH-1 | emulator | Medium | The LR/SC reservation is held on the virtual address, so an SC succeeds after the address is remapped | Disproved by prover | The RISC-V A extension allows an arbitrarily large reservation set, so an SC to a different physical location than the LR may succeed; not an R7 deviation |
| R10-MANARCH-2 | emulator | Medium | The AMO read phase sets `PTE.A` even when the AMO faults on a read-only page | Disproved by prover | The privileged specification allows the A bit to be set by speculation and requires exactness only for D; the replay agrees with native |

Round 10 coverage (hunts with no candidate are not evidence of absence):

- **MANCLI1**: the first half of the CLI section of the manual against `src/cartesi-machine.lua` and the C++ it calls,
  with small harnesses (about 1 s each). Not built: the full valid-template reproducer with an accept-yield guest and the
  PRT player on a poisoned template.
- **MANCLI2**, **MANLUA2**, **MANSTATE**, **MANCOMP**, **MANPRT**: read every checkable statement of their slices;
  MANSTATE built its own Lua builder of the full 2^64 tree and compared it with the machine. MANCOMP, MANPRT and MANLUA2
  ran no end-to-end machine experiment. MANPRT confirmed that every printed code excerpt matches its file. Not
  covered: the computation-hash half of `hash-tree.lua`, the bridge's transaction and journal paths, the
  stored-player reopen paths, and the clock arithmetic of the Dave contracts (out of scope).
- **MANLUA1**, **MANGUEST**, **MANARCH**: read their slices; the guest-tools functions selectors and Merkle tree
  were recomputed. Not examined: `rollup-http-server` under a booted guest, the DTB against the printed devicetree,
  flash and NVRAM placement checks, PLIC registers beyond claim and complete.
- **PROMISES**: read comments, asserts and error messages against the code paths an adversary can reach, with no
  harness. Its main lead, the assert mismatch between the native build (asserts off in `interpret.cpp`) and the uarch
  build (asserts on), yielded no reachable assert beyond R1-VERIFIER-1.

### Round 11 (extra: family expansion of the late findings)

Nine hunters ran, each enumerating every site of one bug shape that rounds 7 to 10 had exposed: stores that precede their
dirty marks, deferred marks and sync ordering, persisted caches trusted on load, configuration masks that are not
honored, wedged operator state, bridge transactions and fees, shared-state deviations in CSRs and devices, shell-outs
and files in the operator code, and the uarch program. They reported 8 raw candidates and dedup merged one duplicate
(FAMPERSISTB-1 into FAMPERSISTA-1), leaving 7. All 7 were proven and all 7 were confirmed by the disproving reviewers (2
Critical, 2 High, 3 Medium), so **round 11 was not clean**. Agents ran on Claude Opus 5.5 (exact ID) at High effort,
except one prover (see Blocked agents).

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R11-FAMCACHE-1 | emulator | Critical | Loading a stored machine trusts its dense hash-tree files (`.dht`): a valid template with one wrong interior node keeps the right root and passes `verify_hash_tree`, then gives wrong proofs and hashes | **Confirmed, Critical** | Reproduced by prover, reviewer and orchestrator; same family and same template-trust judgment as R10-MANCLI1-1; see `BUGS.md` |
| R11-FAMFEES-1 | prt-player-bridge | Critical | The bridge signs 1.2 x `eth_estimateGas` with no worst-case floor, so an honest `joinTournament` or `winMatchByTimeout` runs out of gas when a front-running Sybil join triggers the pairing branch | **Confirmed, Critical** | Reproduced by the reviewer and the orchestrator; **the primary prover was blocked and the proof was produced by the fallback model**; see `BUGS.md` |
| R11-FAMMASK-1 | emulator | High | The native interpreter returns constant `mvendorid`, `marchid` and `mimpid` while the uarch program and the verifiers read the hashed shadow register | **Confirmed, High** | A real R2 disagreement at a before-state that no valid template or input reaches, hence capped at High; see `BUGS.md` |
| R11-FAMOPERATORIO-1 | prt-player-bridge | High | The honest stored player writes and fsyncs one durable file per guest output at every input boundary | **Confirmed, High** | Guest-chosen constant factor and inode exhaustion that wedges the relaunched player; see `BUGS.md` |
| R11-FAMPERSISTA-1 | emulator | Medium | The native page walk stores the PTE A/D update before marking the page dirty (reported twice; FAMPERSISTB-1 merged) | **Confirmed, Medium** | Off the honest path (the stored player snapshots first); see `BUGS.md` |
| R11-FAMPERSISTA-2 | emulator | Medium | `replace_memory_range` discards pending write-TLB dirty marks of the replaced shared range; no crash needed | **Confirmed, Medium** | Deterministic; the player never calls it; see `BUGS.md` |
| R11-FAMMASK-2 | emulator | Medium | Configured `mvendorid`, `marchid` and `mimpid` are never checked at creation, contrary to the manual | **Confirmed, Medium** | Version-mismatch detection (R13) lost; see `BUGS.md` |

Round 11 coverage (hunts with no candidate are not evidence of absence):

- **FAMWEDGE**: journal, nonce records, `state.json`, entries, checkpoints and the manifest against their invariants,
  by reading; no new fault-injection run. The `DaveConsensus` source was not available, so a forever-due job whose
  `eth_call` reverts persistently could not be ruled out.
- **FAMSPEC**: every stored CSR bit and device register against the specification, by reading; no harness. Not diffed
  line by line: the Solidity `UArchStep`, `UArchReset` and `SendCmioResponse` for the HTIF and iflags writes.
- **FAMUARCH**: every abort path compiled into the uarch program, and cycle-budget measurements; clean. Not measured:
  an interrupt, an Sv57 walk and a fault in one mcycle; a byte-for-byte rebuild with the official toolchain; differential
  fuzzing of LR/SC, AMO, compressed and page-walk paths.
- **FAMCACHE** (found R11-FAMCACHE-1): reported an unresolved lead: the `hash_tree.sht` inner nodes are checked on load
  only structurally, and its one attempt to poison an inner sparse node showed no effect before the line was cut
  short. It makes no claim either way.
- **FAMFEES**: gas was measured in an EVM at the Cancun hardfork, not on Prague or Osaka clients; `winInnerTournament`
  and `winLeafMatch` also reach the pairing branch and were not measured.
- **FAMPERSISTA**, **FAMPERSISTB**, **FAMMASK**, **FAMOPERATORIO**: see the coverage notes in `BUGS.md`. Not examined:
  the CLI's `--load clone:`/`sync` handling, the JSON-RPC server's shutdown with shared stores, `game-transport.lua`
  framing and `prt-websocket.lua` frame parsing, and behavior on file systems with reflink error codes.

### Round 12 (extra: second-order family expansion)

Eight hunters ran, each enumerating the sites of one of the shapes that round 11 exposed or opened: two readers of the
same state (hashed shadow against a constant or cached copy), host operations that discard pending in-process state,
decisions made at one chain state and executed at another, per-unit costs of guest-chosen counts, the remaining persisted
structures, the local machine against the JSON-RPC machine, the Lua encoders against the Solidity decoders, and
configuration validation. They reported 4 raw candidates; dedup merged one into R1-ROBUST-3 (SECPERUNIT-2), leaving 3.
Of those, 2 were confirmed (both Critical) and 1 was refuted, so **round 12 was not clean**. The hunter that found the
two confirmed issues was a **fallback run**: the Opus 5.5 hunt for SECCACHE2 was stopped by a safeguard and the
workflow re-ran it on `sonnet`. Every prover and reviewer ran on Opus 5.5 at High effort.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R12-SECCACHE2-1 | emulator | Critical | Loading a stored machine trusts the inner-node hashes of its sparse hash tree (`hash_tree.sht`): a valid template with one wrong dormant inner node loads with the right root and then yields wrong proofs, roots and claims | **Confirmed, Critical** | Reproduced by prover, reviewer and orchestrator; resolves the open lead of round 11; same template-trust judgment as R10-MANCLI1-1; **fallback-sourced discovery**; see `BUGS.md` |
| R12-SECCACHE2-2 | emulator | Critical | Loading a stored machine trusts its dirty-page trees (`.dpt`): a valid template with one dirty interior node under clean ancestors makes every later write under that node invisible to the hash tree | **Confirmed, Critical** | Reproduced by prover, reviewer and orchestrator; same template-trust judgment; **fallback-sourced discovery**; see `BUGS.md` |
| R12-SECPERUNIT-1 | emulator | High | The CLI claim computation fetches every automatic yield's DATA (up to 2 MiB) over JSON-RPC before checking the reason, so a guest makes each mcycle cost about 26 ms | Refuted by reviewer | Reproduced, but a tx-output yield already costs the same fetch, which the CLI needs; the worst case per mcycle does not rise (section 8: average-case only). Covered by R5-DFGUESTOUT-2 and R1-ROBUST-3; folding a length-only query into the R5-DFGUESTOUT-2 fix lowers it |

Round 12 coverage (hunts with no candidate are not evidence of absence):

- **SECSHADOW**: every native reader against its uarch and replay counterpart, register by register, with an executed
  consistency harness over all registers and a comparison of the emulator's constants with `EmulatorConstants.sol`. It
  noted that `is_unreproducible()` reads the configuration copy, not the shadow `iunrep` (a deliberate host
  `write_reg` can make them differ, which section 8 puts out of scope). No differential fuzzing.
- **SECPENDING**: every host operation that runs with pending in-process state, by reading and with differential
  harnesses; no crash variants, no JSON-RPC paths, no CLI stored-revert run.
- **SECGAS**: read every site of the bridge that acts on an earlier observation, against the pinned Dave sources; no new
  EVM measurement. Estimated, not measured: the gas delta of the refund call.
- **SECLOCALREMOTE**: ran both implementations on the same machine; only bare-metal guests, no console redirection, and
  the spawned-server version check compares only the major and minor version.
- **SECEVMSEAM**: ran the Lua encoders against the pinned Solidity decoders on synthetic states. Not covered: whole
  transactions of the Dave consumers, the compiler flags of a real deployment, and `MetaStep` at counter 0.
- **SECCONFIG**: configuration validation at creation, by reading and small experiments. Not covered: odd register
  values (`misa`, `mstatus` SXL/UXL, reserved `satp` modes) through native, uarch and Solidity, and the Solidity PMA lookup
  for non-power-of-two lengths.
- **SECPERUNIT**: tabulated per-unit costs; no reflink file system was available, so the stored player's per-input clone
  cost under the documented reflink requirement was not measured.

### Round 13 (extra: blind adversary personas)

Ten hunters ran, each playing one persona (the input sender, the dishonest claimant, the template supplier, the unlucky
honest operator, the deployment engineer, the author of the consuming contracts, the RISC-V specification lawyer, the
worst-case cost attacker, the application developer and the hash-tree auditor). **They were not shown the list of earlier
findings**, which went only to the dedup step, so this round also measures the audit's recall. They reported 24 raw
candidates. Dedup merged 17 of them into earlier findings and kept 7. Of those 7, 2 were confirmed (both High) and 5 were
refuted or disproved, so **round 13 was not clean**. All agents ran on Claude Opus 5.5 (exact ID) at High effort; no hunt,
prover or reviewer was blocked.

Recall: the 17 duplicates re-found 14 distinct earlier findings (R1-REFEREE-1, R1-REFEREE-2, R2-REFEREE-1,
R2-PLAYER-1, R1-PLAYER-2, R1-PLAYER-3, R1-PLAYER-4, R4-VARSTATE-1, R10-MANCLI1-1, R1-VERIFIER-1, R4-VARRANGE-1, R2-SOLIDITY-1,
R1-ARCH-1/3/4 and R1-GUESTTOOLS-3), most of them from several personas. Every Critical referee and player finding of
round 1 and 2 that a persona could reach was found again without being told about it. Of the 7 new candidates, none was
Critical.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R13-ROLEVERSION-3 | prt-player-bridge | High | The honest player checks only the uarch pristine hash of a deployment, so a verifier build with a different transition function or dispute-constant split is never detected or refused | **Confirmed, High** | Reproduced by prover, reviewer and orchestrator; R13 requires the operator to detect and refuse a mismatch; see `BUGS.md` |
| R13-ROLECOST-2 | prt-player-bridge | High | The honest bridge re-polls every child tournament ever announced, at least twice per tick, so per-move latency grows linearly with the number of Sybil child tournaments | **Confirmed, High** | Reproduced; the reviewer trimmed the claim (no deadline miss shown, observation is not an R12 unit); see `BUGS.md` |
| R13-ROLEVERSION-2 | emulator | High | The build embeds a stale uarch program and pristine hash when only headers changed, so the native interpreter and the uarch diverge and the version check still passes | Refuted by reviewer | Facts hold (the uarch Makefile has no header dependencies and the pristine hash is generated once), but building an audited tag on stale generated artifacts is operator build hygiene on the trusted side (section 4); no section 7 adversary can cause it. A hardening note: track header dependencies in `uarch/Makefile` |
| R13-ROLEAPPDEV-3 | machine-guest-tools | High | `cmt_gio_request` and `rollup gio` accept GIO domains equal to the accepted and rejected reasons, so a guest can forge the outputs root and swallow an input | Refuted by reviewer | Reproduced, but the application forwards queries that the input chooses, which is not a correctly designed application (section 2); the HTTP server already validates the domain. Hardening note: validate the domain in `cmt_gio_request` |
| R13-ROLEAPPDEV-4 | machine-guest-tools | Medium | `rollup-http-server` strips the first two payload characters without checking for `0x` | Refuted by reviewer | The trigger is the application's own violation of the documented payload format; a correctly designed application never sees truncation, and the panic restarts the worker without committing anything |
| R13-ROLESPEC-4 | emulator | Medium | Writes to `mcycle` raise illegal-instruction, and the hpm counters and PMP CSRs are absent | Refuted by reviewer | Deliberate and required by R8 and R13 (`mcycle` is the dispute-grid coordinate), and the manual documents the departure in substance; the absent CSRs are implementation-defined optional features |
| R13-ROLECOST-3 | emulator | High | `sfence.vma` and `satp` writes cost about 17.5K uarch cycles (768 serialized `write_tlb` ECALLs) | Disproved by prover | Within the 2^20 cycles per mcycle that A7 must size for (about 1.7%); the shadow TLB is hashed state, so invalidating its 768 slots must change 768 hashed slots |

Round 13 coverage (hunts with no new candidate are not evidence of absence): each persona walked the whole system from
its seat, so the coverage is by question and not by file. Not reached by the personas that said so: the C++ and Solidity
verifiers against fabricated logs (ROLECLAIMANT looked only at how the referee calls them), the Dave contracts (out of
scope), the bridge's fee and nonce races under a Sybil flood (needs Dave on a chain), `prt-transactions.lua`,
`prt-cast.lua`, `prt-websocket.lua` and `prt-log-history.lua` (ROLECLAIMANT), and the Solidity referee itself (ROLEINPUT, no
EVM for that role).

### Round 14 (extra: blind invariant audit by subsystem)

Eleven hunters ran (ten at a time), each owning one subsystem, deriving its invariants from scratch and attacking them,
and **again without the list of earlier findings**. They reported 20 raw candidates. Dedup merged 18 of them into 14
distinct earlier findings and kept 2 (R14-INVLOGS-1 and R14-INVGUEST-3). One was confirmed and one refuted, so
**round 14 was not clean**, although the one confirmation is a latent High with no reachable trigger. All agents ran on
Claude Opus 5.5 (exact ID) at High effort; no hunt, prover or reviewer was blocked.

Recall: for the second time in a row, blind hunters re-found most of the known issues in their subsystem without being told
about them: the CLINT timer overflow (four hunters), the `sip` writes (two), the misaligned SC and the instret
decrement, the page-walk PMA failures, the referee output aliasing (two), R2-PLAYER-1 and R1-PLAYER-1 (the
honest bridge), libcmt's dynamic offset and bool decoders, the DATA-above-the-buffer abort, and the `replace_memory_range`
mark loss. No blind hunter reported a new Critical.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R14-INVLOGS-1 | emulator | High | The uarch-cycle hash collector throws when the uarch halts on the step that reaches `UARCH_CYCLE_MAX`, although R4 allows it and the verifiers accept the transition | **Confirmed, High** | Reproduced by prover, reviewer and orchestrator with a custom uarch image; with the pristine uarch the trigger is unreachable by bounding arguments, so this is a latent builder-versus-verifier divergence at a boundary that R2 names; see `BUGS.md` |
| R14-INVGUEST-3 | machine-guest-tools | High | The `rollup` CLI with `--utf8-payload` consumes an input with invalid UTF-8 and then fails, so the application can neither read nor reject it on its merits | Refuted by reviewer | Reproduced, but `rollup reject` after the non-zero exit rejects the held input correctly (the reviewer ran that loop), so the interface stays intact and nothing wrong is committed; invalid UTF-8 has no text decoding by definition |

Round 14 coverage (hunts with no new candidate are not evidence of absence):

- **INVINTERP**, **INVCSR**, **INVMMU**: derived and checked about 20 invariants of the interpreter, CSRs, traps, interrupts
  and translation (interrupts versus the native loop, TLB and fetch-cache invalidation, WARL masks, counters); ran
  host differentials of soft-float against x86 and of native against emulated 128-bit arithmetic (2M vectors per operation,
  zero mismatches). Not done: a native-versus-uarch lockstep over a full Linux boot, the worst-case uarch cycles of an
  mcycle (estimated at about 3 flushes plus 2 Sv57 walks, far below 2^20), and rounding mode RMM against hardware.
- **INVHASH**: no candidate; fuzzers used only Keccak and small machines; not run: crash consistency under a real kill,
  OpenMP behavior after fork, SHA-256 trees, and machines large enough to reach the parallel-update thresholds.
- **INVDEVICE**, **INVSTORE**, **INVAPI**, **INVLOGS**, **INVREFEREE**, **INVOPERATOR**, **INVGUEST**: found only
  duplicates plus the two kept candidates. Not examined: `dtb.cpp` line by line, the JSON-RPC server's session lifecycle and
  shutdown races, the CLI's computation-hash runners in depth, differential fuzzing of the forest functions,
  `prt-websocket.lua` past the handshake, the durability of reflink clones, and booting Linux to run the guest-side
  reproducers end to end.

### Round 15 (extra: second opinion on every refuted candidate)

This round hunts for no new defect. It tests the other half of the process: 21 candidates had been refuted or disproved by
one reviewer or prover each, and a wrong refutation would hide a real bug. One independent reviewer (Opus 5.5, High
effort) re-read each refutation against the text of `THREAT_MODEL.md` and `AUDIT.md` and the code, with the instruction
to uphold it unless it could name the exact step that contradicts them. 19 refutations were upheld and 2 overturned.
**One overturn stands as a new confirmation, so round 15 was not clean.** No reviewer was blocked.

| ID | Earlier outcome | Second opinion | Reason |
|---|---|---|---|
| R1-GUESTTOOLS-2 | Refuted by reviewer (round 1) | **Overturned: Confirmed, Critical** | The first reviewer treated the trigger (a guest that leaves a wrong root at an accepted yield) as an application that is not correctly designed, which section 8 lists as out of scope *for the emulator*. `AUDIT.md` keeps components it puts in scope (the honest operator) out of that exclusion, a valid template (section 2) does not require a correctly designed application, section 2 presumes any assignment of guest-writable memory reachable, and R4 holds at every reachable state. The orchestrator reproduced the test and agrees; this is consistent with R1-GUESTTOOLS-1 and R5-DFGUESTOUT-1. See `BUGS.md` |
| R1-HASH-1 | Refuted by reviewer (round 1) | Overturn recorded, **no new finding** | The reviewer examined the stored candidate, which is the referee-model output-index aliasing (bit 63) that the blocked primary hunt reported; the refutation was about a different candidate of the same ID (the step-log hash function of the mcycle verifier, which is ZK-only and stays refuted). The aliasing is already confirmed as R1-REFEREE-2 (the dropped candidate `R1-HASH-blocked`). The test in `bugs/R1-HASH-1/` never tested the aliasing; the reviewer reproduced the aliasing directly |
| R1-SOLIDITY-1, R1-GUESTTOOLS-3, R2-ARCH-1, R6-LCSETUP-1, R6-LCSETUP-2, R7-FPMACHINE-1, R7-FPPRTREST-1, R8-DYNPRTSIM-1, R8-DYNPRTSIM-2, R9-GOALACCEPT-1, R10-MANARCH-1, R10-MANARCH-2, R12-SECPERUNIT-1, R13-ROLEVERSION-2, R13-ROLEAPPDEV-3, R13-ROLEAPPDEV-4, R13-ROLESPEC-4, R13-ROLECOST-3, R14-INVGUEST-3 | Refuted or disproved | Upheld | Each reviewer re-derived the refuting argument against the quoted text of the threat model and agreed with it. For example, R1-SOLIDITY-1 rests on the `InputBox` 64 KiB cap, which the reviewer re-verified in the pinned `rollups-contracts` source, and R10-MANARCH-1/2 rest on the RISC-V text that allows the behavior |

Process note: the 19 upheld refutations support the earlier rounds' reviewing standard, and the 1 genuine overturn shows
the cost of one rule applied too broadly (the "application that is not correctly designed" exclusion). That exclusion is
now read as scoped to the emulator, not to the honest operator.

### Round 16 (extra: R4 at every reachable state)

Round 15's second opinion showed that the calibration given to hunters in rounds 5 to 14 had read the exclusion "an
application that is not correctly designed" too broadly, so honest-operator failures on odd guest-written data may
have been dropped by the hunters themselves. Seven hunters re-swept every honest-operator and emulator path that handles
guest-written data, with the corrected reading in their prompt. They reported 13 raw candidates. Dedup merged 9 into earlier
ones (four hunters independently reported the same stopped-epoch crash) and kept 4. Of those, the provers proved all 4,
the reviewers confirmed 2 (both Critical) and refuted 2, so **round 16 was not clean**. Agents ran on Claude Opus 5.5 (exact
ID) at High effort, except the re-run of one blocked hunt (see Blocked agents).

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R16-RGOUTPUT-1 | prt-player-bridge | Critical | The stored honest player cannot seal, or reopen after a restart, an epoch whose application stopped (a halt, `TX_EXCEPTION` or another manual reason, or the input's mcycle deadline), so the honest claim is never posted | **Confirmed, Critical** | Reproduced by prover, reviewer and orchestrator; found independently by four hunters; the forked player handles the same epochs; see `BUGS.md` |
| R16-RGBRIDGE-2 | prt-player-bridge | Critical | The epoch listener delivers every pending `InputAdded` before the seal, but the referee seals at most 2^24, so more than 2^24 pending inputs crash the listener at `EpochSealed` | **Confirmed, Critical** | Reproduced by prover, reviewer and orchestrator; needs about 2^24 `addInput` calls and a referee that meets A3 (`DaveConsensus` alpha.7 or later; the pinned alpha.6 does not cap the seal); see `BUGS.md` |
| R16-RGOUTPUT-2 | emulator | Critical | The `cartesi-machine` CLI aborts the claim computation by default when the guest's outputs root differs from the host frontier (the CLI counterpart of R1-GUESTTOOLS-2) | Refuted by reviewer | Reproduced, but the CLI is part of the emulator, where the exclusion applies; the check is documented and has an opt-out (`check_outputs_merkle_root:false`), and the player does not call the CLI. A hardening note: report the mismatch without aborting |
| R16-RGCLI-2 | emulator | Critical | The CLI holds a full Merkle proof in memory for every accepted output and writes 2 files per output before reporting the claim | Refuted by reviewer | Linear in the mcycles the epoch covers (about 2.6 KB per output, each output costing several mcycles), so within R12 and A7; the proofs are optional CLI outputs the trusted operator chooses; the reference player is also O(outputs); at most a constant factor (High) even on the most generous reading |

Round 16 coverage (hunts with no new candidate are not evidence of absence):

- **RGEMU**: swept `collect_*`, `log_*`, `send_cmio_response`, `receive_cmio_request` and the proof functions against
  guest-reachable states by reading only; no harness ran. Not done: leaf-by-leaf differentials of collection against
  stepwise `log_step_uarch` at mcycles with interrupts and page-crossing Sv57 fetches, and a combined worst case of the
  uarch cycles per mcycle (relied on the round 13 and 14 bounding arguments).
- **RGUARCH**: the Opus 5.5 hunt was stopped by a safeguard before its last step (a randomized native-versus-uarch
  differential over paging, S/U-mode and CSR states, which never ran); the `sonnet` re-run found nothing. That differential
  remains uncovered, as do most of the soft-float conversions and a line-by-line diff of `UArchStep.sol`.
- **RGPLAYER**, **RGCLI**, **RGSTALL**, **RGOUTPUT**, **RGBRIDGE**: ran bare-metal guests through the real player and the CLI.
  Not done: console blocking with a closed stdout, per-input clone cost without reflinks, the eager all-outputs proof
  generation in `prove_output` (reachable only through the referee model's demonstration), multi-execution CLI epochs with
  odd data at a batch boundary, and `gdbstub.lua`/`evmu.lua`.

### Round 17 (extra: assert and error inventory of the honest operator)

Nine hunters inventoried the honest operator and the Lua libraries file by file, under the corrected reading from round 15
(any guest-written value, adversarial claim and benign fault is in scope). They enumerated about 700 sites between them
(for example INVPLAYERMAIN about 95, INVCLISCRIPT about 228, INVPRT1 33, INVPRT2 about 90 including host API calls).
Eight hunters reported nothing new; the one that did not (INVMODEL) was stopped by a safeguard and its `sonnet` re-run
reported 1 candidate, which the prover disproved. **No new issue was confirmed, so round 17 was clean** (clean-round
count 1). Every adversary-reachable misbehavior the hunters found in their ranges belonged to an already confirmed
family. The strategy is new, but the round is not blind: the hunters saw the list of earlier findings.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R17-INVMODEL-1 | prt-player-bridge | Critical | The honest player aborts when the guest emits outputs beyond the outputs tree (frontier overflow in `flush_pending_outputs`) | Disproved by prover (fallback-sourced candidate) | The assert fires, but the candidate used the wrong capacity: the outputs tree has 2^63 leaves (`ROLLUP_LOG2_MAX_OUTPUT_COUNT = 63`), not 2^24. Overflowing it takes at least 2^63 outputs, hence at least 2^63 mcycles over at least 2^15 inputs that each run near the deadline (about 292 years of emulation), which is outside the resources the deployment is sized for (section 1, R12, A7); a template with 2^63-1 prior outputs needs the same history |

Round 17 coverage (a clean round is not evidence of absence):

- **INVMODEL** is the weak spot: its Opus 5.5 hunter was stopped by a safety classifier partway, so `prt-bridge.lua` from line
  520, the player event handlers in `prt.lua` from line 815, `evmu.lua` and the proof batch builders of `hash-tree.lua` after
  line 330 were not inventoried by it, and the `sonnet` re-run produced only the candidate above. Other hunters covered
  parts of `prt-bridge.lua` and `prt.lua`; `evmu.lua` and the late `hash-tree.lua` builders remain thin.
- **INVTX**: `game-transport.lua` (1230 lines) was only skimmed. The Dave contracts (`Tournament`, `LeafTournament`,
  `DaveConsensus`) are not available, so two questions about event ordering of child tournaments could not be settled.
- **INVPRT3**, **INVPRT4**: no end-to-end crash-injection run; the crash windows were traced by reading. The
  `frontier_forest_expand_leaf` authentication and the Dave `Match` `leftNode` semantics used by the bridge were not
  re-verified.
- **INVCLISCRIPT**: `gdbstub.lua` and `bash.lua` were skimmed; the CLI's root-hash printing runners, console output to a
  closed or blocking stdout, and the per-input clone cost without reflinks were not covered.
- Almost every site was cleared by reading or matched to a known family, so very few harnesses ran in this round.

### Round 18 (extra: blind invariant audit by subsystem, corrected reading)

Eleven hunters ran (ten at a time), each owning one subsystem, deriving its invariants from scratch and attacking them
under the corrected reading of the "application not correctly designed" exclusion, and **without the list of earlier
findings**. They reported 30 raw candidates. Dedup merged 29 of them into 16 distinct earlier findings (among them the
new Critical classes of rounds 15 and 16: the wrong outputs root, the stopped epoch, the DATA above the buffer, the
output aliasing) and kept 1: the `rollup` CLI ignoring errors when it loads `/tmp/merkle.dat`. The prover proved it and
the disproving reviewer refuted it. **No new issue was confirmed, so round 18 was clean: two consecutive clean rounds
(17 and 18), with different strategies, and the audit stops.** No hunt, prover or reviewer was blocked.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R18-B18GUEST-5 | machine-guest-tools | Medium | The `rollup` CLI ignores outputs-tree load errors: a missing or truncated `/tmp/merkle.dat` silently resets or corrupts the outputs tree | Refuted by reviewer | Reproduced, but the trigger is the application itself deleting or overwriting the CLI's private state file, which a correctly designed application does not do (`AUDIT.md`'s rule for `machine-guest-tools` is an application that uses the tools as documented); a missing file at the first call is the intended genesis case; any root committed is deterministic across validators and the goal is not threatened. A hardening note: load into a temporary and refuse on a short file |

Round 18 coverage (a clean round is not evidence of absence):

- **B18INTERP**, **B18CSR**, **B18MMU**: derived and checked about 20 invariants of the core, traps and translation; ran a native-versus-uarch
  differential of about 600 random trials. Not done: bit-exact soft-float against an independent oracle (none installed),
  a composite worst-case mcycle in uarch cycles, and a broad randomized differential over Sv39/48/57 page tables.
- **B18DEVICE**, **B18HASH**, **B18STORE**, **B18LOGS**, **B18API**: by reading and targeted experiments. Not done: `SIGKILL`-mid-update
  experiments on shared stores, power-loss ordering of the `.phtc`, JSON-RPC paths of `get_proof`, the JSON-RPC server's
  fork/rebind/shutdown races, `dtb.cpp` in depth, and a line-by-line diff of the Solidity `UArchStep` against its source.
- **B18REFEREE**, **B18OPERATOR**, **B18GUEST**: not covered by them: the C++ verifiers' internals (B18REFEREE), `prt-cast.lua`,
  `prt-log-history.lua`, `prt-websocket.lua` and the supervisor scripts (B18OPERATOR, skimmed), the Linux `/dev/cmio` driver and
  `rollup-http-client`/`echo-dapp` (B18GUEST).

### Totals across all rounds

| Round | Strategy | Confirmed | Clean? |
|---|---|---|---|
| 1-3 | Planned: threat-model angles | 16, 6, 2 (24) | no |
| 4 | Variant analysis | 6 | no |
| 5 | Data flow | 3 | no |
| 6 | Lifecycle phase | 0 | yes (count 1, reset by round 7) |
| 7 | File partition | 2 | no |
| 8 | Dynamic testing | 2 | no |
| 9 | Attack goals | 1 | no |
| 10 | Manual and promise checking | 2 | no |
| 11 | Family expansion of the late findings | 7 | no |
| 12 | Second-order family expansion | 2 | no |
| 13 | Blind adversary personas | 2 | no |
| 14 | Blind invariant audit by subsystem | 1 | no |
| 15 | Second opinion on 21 refuted candidates | 1 (an overturn) | no |
| 16 | R4 at every reachable state | 2 | no |
| 17 | Assert and error inventory, file by file | 0 | **yes (count 1)** |
| 18 | Blind invariant audit by subsystem, corrected reading | 0 | **yes (count 2): stop** |
| All | | **55 (27 Critical, 13 High, 15 Medium)** | |

Round 6 found nothing new, but round 7 (a different strategy) then did, so it did not satisfy the stop rule. The rule was
met only after two further clean rounds.

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

- `hunt:GOALTIMEOUT` and `hunt:GOALESCAPE`, round 9: each reported that a safety classifier stopped one of its responses
  partway. The workflow did not flag either as blocked (`blocked_by_safeguards` was false) and returned their zero-candidate
  result, so no fallback re-run happened and the primary model did not redo the interrupted part. Their coverage is
  partial, as the Round 9 coverage list states.

- `prove:R11-FAMFEES-1`, round 11: the prover on Opus 5.5 set `blocked_by_safeguards` and produced no proof. The workflow
  re-ran it on `sonnet` (`prove:R11-FAMFEES-1@sonnet`), which proved it. The disproving reviewer ran on Opus 5.5, reran the
  test and confirmed Critical, and the orchestrator reproduced it, so the confirmation does not rest on the fallback
  model's judgment, but the proof of concept was written by it. `BUGS.md` flags this.

- `hunt:SECCACHE2`, round 12: the hunter on Opus 5.5 set `blocked_by_safeguards`; it said a safety classifier stopped its
  response partway and that it would not continue or reconstruct that line of work. The workflow re-ran it on `sonnet`,
  which found R12-SECCACHE2-1 and R12-SECCACHE2-2: **fallback-only discoveries**. Their provers and reviewers ran on
  Opus 5.5. `BUGS.md` flags both.

- `hunt:RGUARCH`, round 16: the hunter on Opus 5.5 set `blocked_by_safeguards` (a safety classifier cut off the last step, a
  randomized differential harness, which never ran). The workflow re-ran it on `sonnet`, which found no candidate. The
  differential it was about to run was not done by any agent; it is listed under Left uncovered.

- `hunt:INVMODEL`, round 17: the hunter on Opus 5.5 set `blocked_by_safeguards` (a classifier stopped it partway through the
  inventory of the encoders and the referee modules). The workflow re-ran it on `sonnet`, whose one candidate the prover
  disproved. The unfinished inventory is described in the Round 17 coverage list.

No prover or reviewer was blocked in any other round, so no issue needed a fallback reviewer or was reported without a
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
- **Native-versus-uarch randomized differential over S/U-mode paging and CSR states.** The round 16 hunt that was about to run it
  was stopped by a safeguard, and no other round ran one over paging, stale TLB entries without `sfence`, `MPRV/SUM/MXR`,
  LR/SC and AMO, page-crossing fetches and PLIC/CLINT sequences. Rounds 8 and 12 ran random-stream differentials, but those
  streams mostly settle in trap loops.
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
  the chain, or restarting the operator process. Fourteen of the 27 Criticals live there (five of them were known by round 3):
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
- **Where the "application that is not correctly designed" exclusion stops.** Section 8 lists it under "Out of scope for the
  emulator", section 2 presumes any assignment of guest-writable memory reachable and does not require a valid template to
  be a correctly designed application, and R4 applies at every reachable state. The text does not say whether the exclusion
  covers the honest operator and the CLI's claim computation. The first reviewers read it as covering all of them; the
  round 15 second opinion read it as scoped to the emulator (R1-GUESTTOOLS-2, R16-RGOUTPUT-1). The audit follows the second
  reading. The threat model should state which components the exclusion covers.
- **Who validates what a stored template carries.** Section 8 says that once a snapshot meets the valid-template conditions,
  nothing it carries outside the hashed state may affect any transition. The conditions are about the contents and the
  root, and no obligation tells the loader to validate the cache files, dirty-page tree and hash-tree files that the load
  adopts (R7-FPUARCH-1, R10-MANCLI1-1, R11-FAMCACHE-1, R12-SECCACHE2-1 and -2). Either the loader must not trust them, or
  the model must say that the template supplier is trusted for them.
- **The listener must enforce A3 on its side.** A3 caps the inputs per epoch, but nothing says that the honest operator's
  epoch listener must apply the same cap when the backlog exceeds it (R16-RGBRIDGE-2), nor which referee behavior it may
  assume at the seal.
- **What a version check must cover.** R13 requires the honest operator to detect and refuse a build/deployment mismatch,
  and section 8 rates a node that cannot detect one as High. Which parts of the deployment must be compared (the pristine
  hash, the verifier code, the split of the dispute constants) is not stated (R13-ROLEVERSION-3).
- **Which entries of the machine configuration are protocol.** Registers such as `mvendorid`, `marchid`, `mimpid` and the
  HTIF masks are configurable, stored, and hashed in some paths and not honored in others (R11-FAMMASK-1/2,
  R10-MANLUA1-1). The model does not list which configuration fields are part of the transition function (R13).

## Cost, strategies and lessons

Measured from the workflow records of the 18 hunting rounds (agent counts, subagent tokens and tool calls are exact; wall time
is derived from file times and is approximate).

### Totals

| Item | Value |
|---|---|
| Rounds | 18 hunting rounds (3 planned by `AUDIT.md`, 15 extra); round 15 only re-reviewed refuted candidates |
| Subagents | 348 (hunters, dedup, provers, reviewers, fallback re-runs) |
| Subagent tokens | about 54.7 million, with about 11,850 tool calls |
| Wall time | about 31 h from the first round launch (06 Nov 23:34 UTC) to the final commit (08 Nov 06:27 UTC); the workflows themselves ran about 24.7 h |
| Models | all agents on Opus 5.5 at High effort, except `sonnet` for re-runs of blocked hunts |

Not included in these numbers: the orchestrator's own tokens (the session was compacted at least three times), the setup
time before round 1 (environment, images and toolchain), and the aborted runs (three launches that left empty outputs and
the round 5 launch that used the wrong model alias).

| Round | Strategy | Agents | Tokens (M) | Confirmed |
|---|---|---|---|---|
| 1 | Planned angles | 50 | 3.8 | 16 |
| 2 | Planned angles | 25 | 2.2 | 6 |
| 3 | Planned angles | 11 | 1.9 | 2 |
| 4 | Variant analysis | 19 | 3.0 | 6 |
| 5 | Data flow | 13 | 2.1 | 3 |
| 6 | Lifecycle phase | 13 | 2.7 | 0 |
| 7 | File partition | 19 | 3.8 | 2 |
| 8 | Dynamic testing | 21 | 4.0 | 2 |
| 9 | Attack goals | 15 | 3.2 | 1 |
| 10 | Manual and promise checking | 17 | 3.3 | 2 |
| 11 | Family expansion | 25 | 4.0 | 7 |
| 12 | Second-order family expansion | 16 | 3.1 | 2 |
| 13 | Blind adversary personas | 24 | 4.1 | 2 |
| 14 | Blind invariant audit by subsystem | 16 | 3.4 | 1 |
| 15 | Second opinion on refuted candidates | 21 | 1.8 | 1 (an overturn) |
| 16 | R4 at every reachable state | 17 | 2.9 | 2 |
| 17 | Assert and error inventory, file by file | 12 | 2.3 | 0 |
| 18 | Blind invariant audit, corrected reading | 14 | 3.1 | 0 |

### Angles

135 distinct angles were defined and run as about 150 hunter runs (rounds 2 and 3 repeated angles); the per-round
lists are in the Extra rounds table: 9 in rounds 1-3, 6 in round 4, 6 in round 5, 8 in round 6, 11 in round 7,
10 in each of rounds 8, 9, 10 and 13, 9 in round 11, 8 in round 12, 11 in each of rounds 14 and 18, 7 in round 16
and 9 in round 17. Round 15 had no angles; it re-reviewed 21 candidates.

### Strategies

Fifteen strategy types over the 18 rounds (the blind invariant audit ran twice, and rounds 11 and 12 use the same method):
planned threat-model angles, variant analysis, data flow, lifecycle phase, file partition, dynamic testing, attack
goals, manual and promise checking, family expansion, blind adversary personas, blind invariant audit by subsystem,
second opinion on refuted candidates, R4 at every reachable state, and the file-by-file assert and error inventory.

### Ranking by confirmed issues

Read this ranking with care: early strategies met the easy bugs, so the order of the rounds inflates the early ones.

| Rank | Strategy | Confirmed | Tokens (M) | Issues per M tokens |
|---|---|---|---|---|
| 1 | Planned angles (rounds 1-3) | 24 | 7.9 | 3.0 |
| 2 | Variant analysis (round 4) | 6 | 3.0 | 2.0 |
| 3 | Family expansion (rounds 11-12) | 9 | 7.1 | 1.3 |
| 4 | Data flow (round 5) | 3, all Critical | 2.1 | 1.4 |
| 5 | Second opinion (15) plus R4 at every reachable state (16) | 3 Critical | 4.7 | 0.6 |
| 6 | Dynamic testing, file partition, manual checking, blind personas | 2 each (8) | about 15 | about 0.5 |
| 7 | Attack goals, blind invariant audit (round 14) | 1 each | 6.6 | 0.3 |
| 8 | Lifecycle, assert inventory, blind invariant audit (round 18) | 0 | 8.1 | 0 |

- Round 15 was the best value per Critical: one found directly, and the calibration error it exposed produced two more in
  round 16.
- Dynamic testing and manual checking are the only strategies that found the crash-ordering bugs and the first
  stored-cache trust bug.
- Blind rounds are a saturation test: rediscovery was 17 of 24, 18 of 20 and 29 of 30 raw candidates in rounds 13, 14
  and 18, and rounds 17 and 18 found nothing new. That is evidence of saturation under these prompts, not proof that
  nothing remains.
- About 28% of the tokens (rounds 6, 9, 14, 17, 18) found at most one issue each.

### Ideas to improve the threat model, ranked

1. **Say which components the exclusion "an application that is not correctly designed" covers.** It sits under "Out of scope
   for the emulator" and was read too broadly for ten rounds (R1-GUESTTOOLS-2, R16-RGOUTPUT-1, R16-RGBRIDGE-2). Add a rule
   that the honest operator computes the canonical claim for any guest state.
2. **Add loader and persistence rules.** A loader validates or recomputes every file not covered by the root (dense,
   sparse and dirty-page trees, page-hash-tree cache, shadow files). Every writer marks dirty before it stores. These two
   rules would have caught about ten issues of rounds 7-12 (R7-FPUARCH-1, R8-DYNPERSIST-1, R9-GOALRESTORE-1,
   R10-MANCLI1-1, R11-FAMCACHE-1, R11-FAMPERSISTA-1/2, R12-SECCACHE2-1/2).
3. **Add operator-side rules.** No benign fault leaves a state from which the operator cannot move; observation and
   persistence cost per guest-chosen count is bounded; gas limits cover the worst-case branch; the listener enforces the
   2^24 cap; the version check lists what must be compared. About twelve issues of the operator family.
4. **List which configuration fields are part of the transition function** and require one source of truth for every
   register across the native interpreter, the uarch program and the verifiers (R11-FAMMASK-1/2, R10-MANLUA1-1,
   R7-FPMEM-1).
5. **Pin down the severity caps.** State how template-supplier trust is rated, that latent or unreachable states are
   capped at High, and that a deviation consistent across paths is Medium. This would have removed several reviewer disputes.
6. **Add an appendix of bug shapes** to the threat model: store-before-mark, trusted-on-load, assert-on-guest-data,
   per-unit counts, estimate-versus-inclusion, ignored masks, 2^63 and 2^51 wraps, capacity caps.

### Ideas to improve the audit prompt and process, ranked

1. **Fix the calibration first and give hunters the shape catalog from round 1.** Run planned angles, then variant analysis,
   data flow, "R4 at every reachable state", family expansion and the file inventory, with one blind round to measure
   recall. Estimated: about 8 rounds and about 25M tokens instead of 18 rounds and 55M.
2. **Do not tell hunters what is "not a bug".** Hunters under-reported what the calibration called out of scope. Have them
   report everything and apply the exclusions at review.
3. **Run a second-opinion round after round 3 and whenever the calibration changes.** It cost 1.8M tokens. Each reviewer
   must quote the exact clause it relies on and say whether it covers that component.
4. **Use blind rounds as the stop test.** Stop when two consecutive blind rounds, after the calibration is fixed, have a
   high rediscovery rate and no new Critical. (Stopping at round 14 on that rule would have missed round 16's Criticals,
   which came from the calibration fix, not from saturation.)
5. **Ship a harness library up front**: the bare-metal guest builder, the mock chain, the stored-player runner, the
   Solidity and EVM harness, and a prebuilt sanitizer copy. Hunters rebuilt these in almost every round.
6. **Let the workflow read its arguments from a file.** Re-inlining 20-30 KB of arguments every round cost orchestrator
   tokens and time. Pin the exact model ID from the start and clean scratch disk automatically.
7. **Handle classifier stops deliberately.** Seven hunts were stopped and re-run on `sonnet`, which gave three
   fallback-only findings. Ask for a "failing test" instead of an "exploit", and retry once on the primary model with a
   rephrased prompt before falling back.

## Conclusion

This audit is finished. It ran 18 rounds, with 348 subagents and about 54.7 million subagent tokens. It stopped under the
requester's rule: rounds 17 and 18 used different strategies and both confirmed no new issue.

**Findings.** 55 confirmed issues: 27 Critical, 13 High and 15 Medium. All are in `BUGS.md`, ordered by severity. Each has
a deterministic failing test under `bugs/`, run with `bugs/run.sh <ID>`. All 55 were run at the end and all fail as
expected on `feature/prt-audit`. 24 other candidates were rejected, each with its reason in the round tables.

**Where the problems are.**
- The honest PRT operator holds most of the Criticals (14 Critical and 8 High in the player and bridge, 3 Critical in the
  referee model). They need no emulator defect. The player and bridge crash on guest or relayed data, lose their claim
  after a restart, or pay costs that grow with the adversary's inputs or the application's age.
- The emulator's Criticals are verifier and CLI aborts on guest or relayed data, and stored machines that trust files
  outside the hashed state when they load. Its Medium issues are mostly verifier deviations at unreachable states and
  trailing data accepted without effect.
- `machine-solidity-step` has two High issues and `machine-guest-tools` has two Critical decoder issues.
- No soundness failure was found in the transition function, or in the verifiers at reachable states.

**What this audit does not show.**
- It does not show that no further issue exists. Blind rounds re-found nearly everything (17 of 24, 18 of 20 and 29 of 30
  raw candidates), which shows saturation under these prompts, not completeness.
- The calibration error on the "application not correctly designed" exclusion stood from round 5 to round 14. The classes
  swept after it was fixed (R4 at every reachable state, round 16, and the file-by-file inventory, round 17) are the best
  covered. Other classes got less attention.
- Seven hunts and one proof were stopped by safeguards. Three issues were found only on fallback models and are flagged
  in `BUGS.md`. The areas left uncovered and the threat-model gaps are listed above and should be settled before the next
  audit.
- The Solidity verifier results rest on a hunter's EVM harness. The orchestrator could not re-run it, because the
  package install was denied.
- `THREAT_MODEL.md`, `AUDIT.md`, `src/`, `uarch/` and `doc/` were not modified.

**Next audit.** It should start only after the relevant bugs above are fixed, so that it audits the fixed code and not
issues already known. Before it starts:
1. Settle the threat-model gaps in "Gaps in the threat model", at least the scope of the exclusion, the loader and
   persistence rules, and the severity caps.
2. Apply the process changes in "Cost, strategies and lessons": fix the calibration, give hunters the catalog of bug shapes,
   and ship the harness library.
3. Re-run `bugs/run.sh` for every fixed issue. Each test that now exits 0 becomes a regression test, and a test that still
   exits 1 means the fix is incomplete.
4. Keep one blind round as the stop test, run after the calibration is fixed.

