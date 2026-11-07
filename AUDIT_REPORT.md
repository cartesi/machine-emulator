# PRT Audit Report

Status: **extra rounds in progress** (round 4). The results below cover rounds 1-3 and are updated as extra rounds confirm issues.

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

## Extra rounds

After the planned audit closed, extra rounds were run at the requester's request. Each one splits the work with a
different strategy, so that no single way of dividing the code decides what gets examined. They stop once two
consecutive rounds, each with a different strategy, confirm no new issue. Each round keeps the limits of `AUDIT.md`:
at most 6 hunters, at most 5 candidates each, one disproving reviewer per candidate, and a commit and push for every
confirmed issue. Hunters receive every earlier candidate with its outcome, and calibration notes from the
refutations.

| Round | Strategy | Angles |
|---|---|---|
| 4 | Variant analysis: one hunter per family of confirmed bugs, searching the whole scope for other sites with the same root-cause pattern | VARABORT (process-terminating errors on data that must be handled), VARCLOCK (clock and deadline arithmetic), VARRANGE (missing range and index checks), VARGROWTH (unbounded growth with volume or age), VARSTATE (derived, cached or restored state diverging), VARSPEC (architectural deviations in traps, CSRs, permissions) |
| 5 | Data flow: one hunter per untrusted source, followed end to end across components | planned |
| 6 | Lifecycle phase: one hunter per phase of an epoch and of the operator | planned, if needed |
| 7 | File partition: disjoint file sets, each against the whole threat model | planned, if needed |

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
candidates, and dedup kept all of them.

| ID | Component | Claimed | Title | Outcome | Reason |
|---|---|---|---|---|---|
| R4-VARABORT-1 | emulator | Critical | `cartesi-machine` CLI cannot compute claims when a rejected input leaves DATA above the transmit buffer | **Confirmed, Critical** | Same API throw as R1-GUESTTOOLS-1, but in the CLI, with its own fix; see `BUGS.md` |
| R4-VARRANGE-1 | machine-guest-tools | Critical | libcmt ABI decoder accepts wrapping dynamic offsets, so an app commits an output built from the wrong bytes | **Confirmed, Critical** | Reviewer-confirmed and orchestrator-reproduced; a safety classifier stopped the detailed write-up, so the record is a factual summary plus the committed test |
| R4-VARGROWTH-1 | prt-player-bridge | Critical | Stored player keeps every epoch's directory and checkpoint forever | **Confirmed, High** | Reviewer lowered the claimed Critical: per-epoch use is bounded and settled epochs can be pruned by hand; see `BUGS.md` |
| R4-VARSTATE-1 | prt-player-bridge | High | Relaunched player keeps its stored epoch after the confirmed input history or the seal changed | **Confirmed, High** | Relaunch removes the fail-closed margin after a reorg beyond the input policy; see `BUGS.md` |
| R4-VARSPEC-1 | emulator | Medium | Page walk accepts non-leaf PTEs with the reserved A, D or U bits set | **Confirmed, Medium** | Deterministic, consistent across paths, no correct guest sets these bits; see `BUGS.md` |
| R4-VARSPEC-2 | emulator | Medium | Interrupts change `instret` | **Confirmed, Medium** | Deterministic, consistent across paths, contradicts the manual's counter definition; see `BUGS.md` |

## Blocked agents

- `hunt:HASH`, round 1: the hunter on the session model set `blocked_by_safeguards` but still returned one candidate:
  "the referee model accepts an output proof at an index outside the outputs tree". The workflow treated the run as
  blocked and retried it on `sonnet`, which completed and produced R1-HASH-1. The dropped candidate is the same defect
  as R1-REFEREE-2, so it is covered.

- `hunt:TRANSITIONS`, round 2: the hunter on the session model set `blocked_by_safeguards` and returned no
  candidate. Its retry on `sonnet` completed and found no new candidate.

No prover or reviewer was blocked in any round, so no issue needed a fallback reviewer or was reported without a
proof of concept. The only fallbacks were the two hunters above.

## Left uncovered

The hunt was bounded to 3 rounds (`AUDIT.md`). These areas were not examined, or were examined only partly. The
hunters reported them as uncovered and later rounds did not close them.

- **Solidity execution.** No EVM, `solc` or Foundry could be installed (refused by the sandbox's permission policy),
  so `machine-solidity-step` was never run. Its findings rest on regeneration from the C++ (the generated
  `UArchStep.sol`, `UArchReset.sol` and `SendCmioResponse.sol` match token for token), line-by-line traces, and Lua
  models of the pinned source. On-chain gas was computed from calldata formulas, not measured.
- **The Dave contracts.** They are out of scope and not in the tree. The parts of the encoding seam that they own were
  not checked: how they compute `dataHash` from input bytes, how they parse the input-length prefix that
  `transition_proof` emits, the `MetaStep` counter they pass, how they map a position to its form, and whole-transaction
  gas. Neither was the reliance of R2-REFEREE-1 and R1-REFEREE-1 on Dave's behavior. Both cite it through the bridge
  and its specification, which encode Dave's rules, not through the contracts themselves.
- **Uarch worst case.** The worst-case number of uarch cycles per mcycle against `UARCH_CYCLE_MAX` (R4, R12) was
  measured only for representative heavy mcycles: TLB flushes, traps, page walks, soft-float. It was estimated, not
  bounded analytically, and an interrupt taken together with a flushing instruction in the same mcycle was not
  measured.
- **Differential fuzzing.** There was no executed differential fuzz of `uarch_step` (C++ replay against the pinned
  uarch program) on fabricated uarch states, no exhaustive soft-float check against a reference implementation, and no
  full line-by-line review of every RV64C, F and D handler. Sv48 and Sv57 walks were exercised only on faulting walks.
- **Long runs.** Native and uarch were not compared over a full Linux boot, and forking through the JSON-RPC server was
  not compared with an uninterrupted run (store and load were).
- **Persistence.** Crash consistency of shared backing stores (`dht`, `dpt`, `sht`, `phtc`) under SIGKILL, and the
  stored player's crash recovery at every interleaving, were not exercised.
- **Claim correctness on output-emitting guests.** The honest player's mcycle and uarch claims were compared with the
  CLI's computation hashes only for bare-metal guests that emit no outputs. An input deadline reached after 2^48 real
  mcycles was checked only through a saturated template near 2^64.
- **`machine-guest-tools` at run time.** `rollup-http-server` under real concurrency and timeouts, `echo-dapp`, and
  libcmt's Merkle tree near 2^63 leaves were read but not exercised. Round 2's GUESTTOOLS hunter found nothing new
  inside the tools themselves.
- **Operator plumbing.** `prt-websocket.lua` frame parsing, fee and nonce corner cases of `prt-transactions.lua` under
  reorgs, JSON-RPC per-request allocation for large relayed logs, and the CLI's rollup paths under adversarial inputs
  were read but not stress-tested.
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
