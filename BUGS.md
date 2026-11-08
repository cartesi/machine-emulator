# Bugs

Confirmed issues of the PRT audit, ordered by severity. Severities and rules follow `THREAT_MODEL.md`. The process
and every rejected candidate are in `AUDIT_REPORT.md`. Run a test with `bugs/run.sh <ID>`; it fails while the bug is
present.

Flags required by `AUDIT.md`:

- **Solidity execution.** The tests `bugs/R2-SOLIDITY-1` and `bugs/R2-SOLIDITY-2` model the pinned
  `machine-solidity-step` source; they do not run it. In round 8 a hunter did run the pinned contracts (solc-js plus
  `revm`) and executed the R2-SOLIDITY-2 revert on the last leaf, and saw out-of-range TLB indices revert in
  checked arithmetic, which is the R2-SOLIDITY-1 family; the orchestrator could not re-run that harness (its install
  of the EVM was refused). The C++ halves and every other test run real code.
- **Fallback models.** Every reviewer, and every prover except one, ran on the primary model (Opus 5.5). One issue, R8-DYNPERSIST-1,
  was *found* only by a fallback-model hunter (`sonnet`), after the primary hunt for that angle was stopped by a
  safeguard; its proof of concept and its review ran on the primary model. Likewise the proof of concept of
  R11-FAMFEES-1 was written by the fallback model (the primary prover was blocked); its hunter and its reviewer, who
  reproduced it, ran on the primary model. R12-SECCACHE2-1 and R12-SECCACHE2-2 were also *found* only by the fallback
  hunter (the primary hunt was stopped by a safeguard); their provers and reviewers ran on the primary model.
- **Proofs of concept.** Every issue has one; none is reported without a test.

| ID | Title | Component | Cited rules | Severity |
|---|---|---|---|---|
| [R1-GUESTTOOLS-1](#r1-guesttools-1) | Honest PRT player aborts for good when a guest yield's DATA exceeds the transmit buffer | PRT player and bridge (yield handling) | R4, section 1 completeness, section 2 reachable state, section 4, A7 | Critical |
| [R1-GUESTTOOLS-2](#r1-guesttools-2) | The honest PRT player asserts that the outputs Merkle root left by the guest equals its own frontier, so a guest that leaves any other value at an accepted yield aborts claim computation for good | `prt-player-bridge` (`doc/recipes/prt.lua`) | R4, section 1 completeness, section 4, A5, section 8 | Critical |
| [R1-PLAYER-1](#r1-player-1) | Relaunched honest bridge abandons its own claim when an adversary joined that commitment first | PRT player and bridge (claim binding after restart) | R4, A7, section 1 completeness, section 7 | Critical |
| [R1-PLAYER-2](#r1-player-2) | Eight-entry input-boundary cache makes reaching a disputed position cost about n/5 whole inputs | PRT player and bridge (machine cache, replay cost) | R12, A7, R4, section 1 completeness, section 7 | Critical |
| [R1-PLAYER-3](#r1-player-3) | Player reads the previous epoch's seal with one unpaged `eth_getLogs` and crash-loops once the chain outgrows the node's range limit | PRT player and bridge (epoch discovery) | R4, A7, section 4, section 1 completeness | Critical |
| [R1-PLAYER-5](#r1-player-5) | Next-epoch inputs run between two ticks of the current dispute, so an input flood delays honest responses past the clocks | PRT player and bridge (scheduling, deadlines) | R4, A7, R12, section 1 completeness, section 7 | Critical |
| [R1-REFEREE-1](#r1-referee-1) | A late Sybil re-post of the honest claim cuts the honest claim's clock to one block | PRT referee model (tournament joining, clocks) | A7, section 1, section 2 honest claim, section 7, the manual's clock rule | Critical |
| [R1-REFEREE-2](#r1-referee-2) | Output proofs are not range-checked: every output is accepted again at index i - 2^63 | PRT referee model (output verification), `cartesi.hash-tree` | A5, section 1 soundness, section 4, R11, R9 | Critical |
| [R1-ROBUST-1](#r1-robust-1) | Honest player keeps every tx-output payload of an input in memory, so a guest drives its memory up without bound | PRT player and bridge (output collection) | R8, R12, R4, A7, section 1 completeness, section 4 | Critical |
| [R1-VERIFIER-1](#r1-verifier-1) | Uarch step verifier aborts the process on a relayed log against a fabricated before-state | emulator (uarch step verifier), PRT referee model | Section 4, R10, R3, R2, section 1 completeness, section 7 | Critical |
| [R2-PLAYER-1](#r2-player-1) | A settled epoch's bridge cancels the next epoch's pending honest transactions through the shared journal | PRT player and bridge (transaction scheduling across epochs) | R4, R12, A7, section 1 completeness, section 2 honest operator's path | Critical |
| [R2-REFEREE-1](#r2-referee-1) | At a sealed uarch leaf, the honest claim gets only the opponent's clock to prove, with no timeout win | PRT referee model (uarch leaf settlement) | A7, A1, R4, section 1 completeness, section 5, section 7 | Critical |
| [R3-PLAYER-1](#r3-player-1) | Honest player cannot sign a `winLeafMatch` proof for inputs of about 37 KB or more, because calldata goes to `cast` as one shell argument | PRT player and bridge (transaction signing) | R4, R12, A7, section 1 completeness, section 4, section 8 Critical | Critical |
| [R4-VARABORT-1](#r4-varabort-1) | `cartesi-machine` CLI cannot compute claims when a rejected input leaves DATA above the transmit-buffer size | emulator (`cartesi-machine` CLI, cmio computation-hash modes) | R4, R2, section 1 completeness, section 2, section 4, section 8 Critical | Critical |
| [R4-VARRANGE-1](#r4-varrange-1) | libcmt ABI decoder omits a bounds check on a decoded dynamic offset | `machine-guest-tools` (libcmt ABI decoder) | Section 1 goal, section 2 correctly designed application, section 4, section 7, `AUDIT.md` guest-tools rule | Critical |
| [R5-DFGUESTOUT-1](#r5-dfguestout-1) | Player and CLI read the outputs root using the guest's `tohost` DATA as its length, so a valid template with DATA other than 32 crashes both on an oversized no-op input | PRT player and bridge, emulator (`cartesi-machine` CLI) | R4, R2, A5, section 2 valid template, section 4, section 1 completeness, section 8 Critical | Critical |
| [R5-DFGUESTOUT-2](#r5-dfguestout-2) | `cartesi-machine` CLI keeps every tx-output payload in memory and writes every report or rejected output to its own file by default | emulator (`cartesi-machine` CLI, cmio computation-hash modes) | R8, R12, R4, A7, section 1 completeness, section 4, section 8 Critical | Critical |
| [R5-DFINPUT-1](#r5-dfinput-1) | libcmt `cmt_abi_get_bool` returns success for ABI words that are not a valid bool | `machine-guest-tools` (libcmt ABI decoder) | Section 2 correctly designed application, section 4, section 7, `AUDIT.md` guest-tools rule | Critical |
| [R7-FPUARCH-1](#r7-fpuarch-1) | An interrupted mark-dirty leaves a dirty page under clean ancestors in a shared stored machine, so after a reload the page is never re-hashed and the root hash goes stale | emulator (dirty-page tree, stored machines) | R9, R2, R4, section 1 completeness, section 2 honest operator's path | Critical |
| [R8-DYNPLAYERFAULT-1](#r8-dynplayerfault-1) | The honest bridge's signer wedges for good when its journal holds a candidate the node does not have, signed near the fee or tip ceiling, and that candidate's job is no longer due | `prt-player-bridge` (`prt-transactions.lua`, `prt-bridge.lua`) | R4, section 1 completeness, section 2 honest operator's path, A7 | Critical |
| [R10-MANCLI1-1](#r10-mancli1-1) | Loading a stored machine trusts its page hash-tree cache (`hash_tree.phtc`, outside the hashed state), so a valid template with a poisoned cache reports the right root and then computes wrong hashes and proofs | emulator (`page_hash_tree_cache`, stored machines, CLI and PRT player load) | R1, R9, R2, R4, section 2 valid template, section 8 | Critical |
| [R11-FAMCACHE-1](#r11-famcache-1) | Loading a stored machine trusts its dense hash-tree files (`<range>.dht`): a valid template with one wrong interior node keeps the right root and passes `verify_hash_tree`, then gives proofs and hashes that are wrong | emulator; dense hash-tree files of stored machines (CLI `--load`, JSON-RPC load, PRT player) | R1, R9, R2, R4, R10, section 2 valid template, section 8 | Critical |
| [R11-FAMFEES-1](#r11-famfees-1) | The bridge signs `1.2 x eth_estimateGas at latest` with no worst-case floor, so an honest `joinTournament` or `winMatchByTimeout` runs out of gas when a front-running Sybil join triggers the pairing branch | `prt-player-bridge`; `doc/recipes/prt-transactions.lua` | R4, A7, section 1 completeness, section 2 honest operator's path | Critical |
| [R12-SECCACHE2-1](#r12-seccache2-1) | Loading a stored machine trusts the inner-node hashes of its sparse hash tree (`hash_tree.sht`): a valid template with one wrong dormant inner node loads with the right root, then yields wrong proofs, roots and claims | emulator; sparse hash tree file of stored machines (CLI `--load`, JSON-RPC load, PRT player) | R1, R9, R2, R4, R10, section 2 valid template, section 8 | Critical |
| [R12-SECCACHE2-2](#r12-seccache2-2) | Loading a stored machine trusts its dirty-page trees (`.dpt`): a valid template with one dirty interior node under clean ancestors loads and verifies cleanly, then every later write under that node is invisible to the hash tree | emulator; dirty-page tree files of stored machines (CLI `--load`, JSON-RPC load, PRT player) | R1, R9, R2, R4, R10, section 2 valid template, section 8 | Critical |
| [R1-PLAYER-4](#r1-player-4) | Epoch listeners fetch, keep and re-sort every InputBox log of every application | PRT player and bridge (input observation) | Section 4, R12, A7, R4, section 7 | High |
| [R1-ROBUST-3](#r1-robust-3) | Each guest automatic yield costs the honest player a host-API round trip, a guest-chosen constant-factor slowdown | PRT player and bridge (run loop, computation-hash collection) | R12, A7, section 8 High | High |
| [R1-TRANSITIONS-1](#r1-transitions-1) | Uarch computation-hash builder's fast reset restores only dirtied uarch-RAM words | emulator (uarch computation-hash builder) | R2, R13, R5, section 2 transition form | High |
| [R2-ROBUST-1](#r2-robust-1) | Every past epoch's bridge re-observes and retains the full shared log history on every pass | PRT player and bridge (dispute bridge observation) | R12, A7, R4, section 4, section 8 High | High |
| [R2-SOLIDITY-1](#r2-solidity-1) | Uarch verifiers accept a `WRITE_TLB` ECALL with out-of-range indices, writing a TLB slot image to any leaf where native throws | emulator (uarch step verifier), `machine-solidity-step` (`EmulatorCompat.writeTlbECALL`) | R2, R3, R13, A6, section 8 High | High |
| [R2-SOLIDITY-2](#r2-solidity-2) | On-chain `Memory.validateStrideLength` off-by-one rejects every access to the last leaf | `machine-solidity-step` (`Memory.sol`) | R2, R3, R10, section 8 High | High |
| [R4-VARGROWTH-1](#r4-vargrowth-1) | Honest stored player never removes settled epochs' directories or checkpoints, so disk use grows with the application's age | PRT player and bridge (stored player retention) | Section 1 resources, R12, A7, R4, section 2, section 8 High | High |
| [R4-VARSTATE-1](#r4-varstate-1) | After a deep reorg aborts the honest player, the relaunched player silently keeps its stored epoch and claims over replaced inputs | PRT player and bridge (stored epoch reopen) | R4, R2, A3, section 1 completeness, section 2 honest operator's path, section 8 High | High |
| [R11-FAMMASK-1](#r11-fammask-1) | The native interpreter returns constant `mvendorid`, `marchid` and `mimpid` while the uarch program and the uarch and Solidity verifiers read the hashed shadow register | emulator; machine-ID CSRs (`interpret.cpp` against `uarch`) | R2, R7, R13, section 8 High | High |
| [R11-FAMOPERATORIO-1](#r11-famoperatorio-1) | The honest stored player writes and fsyncs one durable file per guest output at every input boundary, so its persistence cost and inode use grow with the number of outputs | `prt-player-bridge`; stored player output persistence (`doc/recipes/prt.lua`) | R12, A7, R4, section 8 High | High |
| [R13-ROLECOST-2](#r13-rolecost-2) | The honest bridge re-polls every child tournament ever announced, at least twice per tick, so its per-move latency grows linearly with the number of Sybil child tournaments | `prt-player-bridge`; `doc/recipes/prt-bridge.lua` and `prt-log-history.lua` | R12 (loosely), A7, section 1 completeness, section 8 High | High |
| [R13-ROLEVERSION-3](#r13-roleversion-3) | The honest player checks only the uarch pristine hash of a deployment, so a verifier build with a different transition function or dispute-constant split is never detected or refused | `prt-player-bridge`; deployment checks of `doc/recipes/prt-player.lua` and `prt-bridge.lua` (`read_geometry`) | R13, A6, section 1 completeness, section 8 High | High |
| [R14-INVLOGS-1](#r14-invlogs-1) | The uarch-cycle hash collector throws when the uarch halts on the step that reaches `UARCH_CYCLE_MAX`, although R4 allows it and the verifiers accept the transition | emulator; `collect_uarch_cycle_root_hashes` and `collect_uarch_cycle_bundle` (`src/machine.cpp`), `uarch_step` | R4, R2, section 8 High | High |
| [R1-ARCH-1](#r1-arch-1) | CLINT `mtimecmp`-to-cycle conversion wraps, raising spurious timer interrupts (and none for `mtimecmp == 0`) | emulator (CLINT, timer interrupts) | R7, section 8 Medium | Medium |
| [R1-ARCH-2](#r1-arch-2) | Misaligned SC.W/SC.D without a matching reservation fails silently instead of trapping | emulator (atomics, LR/SC) | R7, section 8 Medium | Medium |
| [R1-ARCH-3](#r1-arch-3) | Page walk ignores PMA failures on PTE accesses | emulator (address translation) | R7, section 8 Medium | Medium |
| [R1-ARCH-4](#r1-arch-4) | S-mode `sip` writes can set and clear the read-only STIP and SEIP bits | emulator (supervisor interrupt CSRs) | R7, section 8 Medium | Medium |
| [R2-VERIFIER-2](#r2-verifier-2) | Send-cmio-response verifier accepts read accesses carrying unchecked `written`/`written_hash` fields | emulator (input-delivery log verifier) | R3, R11, section 4, section 8 Medium | Medium |
| [R3-REFEREE-1](#r3-referee-1) | Referee narration raises on adversary-chosen data inside the referee coroutine, killing the referee | PRT referee model (narration on the referee's fatal path) | A5, section 4, section 5, section 7, section 8 Medium | Medium |
| [R4-VARSPEC-1](#r4-varspec-1) | Page walk accepts non-leaf PTEs with the reserved A, D or U bits set instead of raising a page fault | emulator (address translation) | R7, section 8 Medium | Medium |
| [R4-VARSPEC-2](#r4-varspec-2) | Each interrupt taken decrements `instret`/`minstret` | emulator (counters, traps) | R7, the manual's definition of `icycleinstret`, section 8 Medium | Medium |
| [R7-FPMEM-1](#r7-fpmem-1) | A PLIC claim/complete write clears the M-mode software-written `mip.SEIP` bit, because the PLIC signal and the software bit share one stored bit | emulator (PLIC, supervisor external interrupt) | R7, section 8 Medium | Medium |
| [R8-DYNPERSIST-1](#r8-dynpersist-1) | `write_memory`, `write_word` and `fill_memory` store the data into shared RAM before marking the page dirty, so a process stop in between leaves a stored machine whose hash tree does not commit to its contents | emulator (`src/machine.cpp`, shared stored machines) | R9, R2, section 8 Medium | Medium |
| [R9-GOALRESTORE-1](#r9-goalrestore-1) | Mcycle hash collection defers the dirty marks of page-walk A/D writes to the end of each sampling period, so a process stop during collection leaves a shared stored machine whose hash tree does not commit to its contents | emulator (`collect_mcycle_root_hashes`, shared stored machines) | R9, R2, section 8 Medium | Medium |
| [R10-MANLUA1-1](#r10-manlua1-1) | The HTIF halt command ignores the `ihalt` availability mask, so a machine configured with `ihalt = 0` still halts | emulator (HTIF device) | R7, section 8 Medium | Medium |
| [R11-FAMMASK-2](#r11-fammask-2) | Configured `mvendorid`, `marchid` and `mimpid` are accepted and never checked for newly created machines, although the manual says they are checked at instantiation | emulator; machine configuration validation | R13, R7, section 8 Medium | Medium |
| [R11-FAMPERSISTA-1](#r11-fampersista-1) | The native interpreter's page walk stores the PTE accessed/dirty update into shared RAM before marking the page dirty, so a stop in between leaves a stale hash tree in a shared stored machine | emulator; `write_ram_uint64` on the native `state_access` path (plain `run()`) | R9, R2, section 8 Medium | Medium |
| [R11-FAMPERSISTA-2](#r11-fampersista-2) | `replace_memory_range` discards the write-TLB dirty marks still pending against the replaced shared range, so the stored hash tree no longer commits to its contents (no crash needed) | emulator; `replace_memory_range` on a `SHARING_ALL` machine | R9, R2, section 8 Medium | Medium |

---

## R1-GUESTTOOLS-1

**Honest PRT player aborts for good when a guest yield's DATA exceeds the transmit buffer**

- **Severity:** Critical (R4 violated at a reachable state on the honest operator's path; a crash caused by data
  the honest operator must process).
- **Component and area:** PRT player and bridge (honest operator); yield handling in the input driver. The hunter
  that found it worked the `machine-guest-tools` angle, but the defect is in the player.
- **Cited rules:** R4 (from any reachable state the honest operator can compute the claim and produce every proof);
  section 1 completeness failure; section 2 (reachable state, correctly designed application, honest operator's
  path); section 4 (yield data is opaque guest data); A7 (the operator then misses its deadlines).
- **Location:**
  - `doc/recipes/prt.lua:955-959`: the `receive_cmio_request` wrapper calls `machine:receive_cmio_request()` with
    no guard.
  - Its callers: `doc/recipes/prt.lua:1375` (`run_to_stop`, at every automatic yield while outputs are collected) and
    `doc/recipes/prt.lua:1985` (`run_to_input_mcycle_offset`, at every manual-yield fixed point). The latter is used
    by `input_added`, replays, proof production and bundle opening.
  - `src/machine.cpp:1993-1995`: `receive_cmio_request` throws `CMIO request data is too large` when DATA exceeds
    the 2 MiB transmit buffer and the yield is not a progress report.
  - `doc/recipes/prt.lua:2047-2075` (`event_handler.input_added`) clears `epoch_pair` and counts the input before
    running it.

### Problem

The guest writes the whole `tohost` word, so a yield's DATA can be any 32-bit value. The emulator handles such a
state normally: it hashes it, reverts on rejection, and resumes after automatic yields. The player, however, reads
every yield through `receive_cmio_request`, and that call throws on large DATA, including for:

- a rejected input, whose DATA the manual says is ignored ("On reject, `DATA` is ignored", `doc/README.md:7591`);
- a report, which the player ignores anyway.

Once `input_added` has thrown, retrying on the same player does nothing, `epoch_sealed` fails with "epoch is not
open", and a restarted player replays the input and throws again. The honest operator can never seal the epoch,
compute its claim, or produce proofs for that input.

### Evidence and test

- Test: `bugs/R1-GUESTTOOLS-1/test.lua`, with the bare-metal guest `yield.S`, `link.ld` and `build.sh`. Run
  `bugs/run.sh R1-GUESTTOOLS-1`.
- `yield.S` builds a valid template, an rx-accepted yield with the empty outputs root, which the player's own
  `assert_rolling_template` accepts. The test drives the real forked player (`prt.new_forked_player`) through one
  input in three variants:
  - A: a manual rx-rejected yield with DATA `0x200001`;
  - B: an automatic tx-report with DATA `0x200001`, then an rx-accepted yield;
  - C: an automatic tx-output with DATA `0xffffffff`, then an rx-rejected yield.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - in every variant, `input_added` raises `prt.lua:957: CMIO request data is too large`;
  - a retry is skipped, and `epoch_sealed` fails with `epoch is not open`;
  - a restarted player raises again;
  - the bare machine runs through the same yields and computes its hash without error.
- The prover also checked a fix: skipping the call when DATA exceeds the buffer makes the test pass, and every
  variant seals at the hash the bare machine reaches.

### Scenario and reachability

1. An attacker sends an advance-state input to an application that, on rejecting it, leaves a large value in DATA,
   which the manual allows.
2. The honest operator cannot decline the input, because it is on-chain, so its player stops computing the epoch.
3. The operator misses its deadlines, its claim is eliminated, and a dishonest claim can settle: a completeness
   failure.

Variants B and C need a guest that breaks the length convention, which section 2 presumes reachable ("any assignment
of guest-writable memory and registers") and which section 4 grants to an input that subverts the guest. None of the
variants is a stall: the machine reaches a normal fixed point or resumes.

### Possible solution

Do not read the transmit buffer blindly at every yield:

- read `htif_tohost_cmd`, `htif_tohost_reason` and `htif_tohost_data` as registers;
- skip the buffer for rejections, unknown reasons and reports;
- for rx-accepted, read the outputs root from the first 32 bytes of the transmit buffer, matching what the
  extraction proof authenticates (A5);
- for an oversized tx-output, apply a deterministic policy, for example treat the output as unprovable, and never
  raise.

Claim computation depends only on state hashes and must not depend on output bookkeeping.

### Risks

- Of the issue: one input to such an application disables every honest player for the epoch, so a wrong state and
  wrong outputs can settle.
- Of the fix: the root the player reads must match the on-chain extraction exactly. Any policy for oversized outputs
  must stay consistent with A5, since such an output can never be proven. Changing the C++ `receive_cmio_request`
  instead would be a host API change other callers rely on, though not a change of the transition function.

---

## R1-GUESTTOOLS-2

**The honest PRT player asserts that the outputs Merkle root left by the guest equals its own frontier, so a guest
that leaves any other value at an accepted yield aborts claim computation for good**

- **Severity:** Critical (`THREAT_MODEL.md` section 8: violating a rule at a reachable state, or anywhere on the
  honest operator's path). **Overturned on a second opinion in round 15.** Round 1's reviewer refuted it as out of
  scope (the trigger needs an application that is not correctly designed); the round 15 reviewer showed that this
  reading does not follow the text: the section 8 exclusion "an application that is not correctly designed" is listed
  under "Out of scope for the emulator" and `AUDIT.md` keeps findings in components it puts in scope (the honest
  operator) out of that exclusion; a valid template (section 2) does not require a correctly designed application; and
  section 2 presumes any assignment of guest-writable memory reachable. R4 then requires the honest operator to
  compute the claim from that state. Reproduced by the orchestrator.
- **Component and area:** `prt-player-bridge`; player output collection (`flush_pending_outputs`) on a manual
  rx-accepted yield.
- **Cited rules:** R4 (honest completeness), section 1 completeness failure, section 4 (the outputs root and payloads
  are opaque guest data), A5; section 8 Critical. The first reviewer's counter-arguments (a buggy or subverted guest
  controls the root anyway, and a corrupted guest-tools tree is its own finding) are fair but do not remove the R4
  breach.
- **Location:** doc/recipes/prt.lua:1385-1394 (`flush_pending_outputs`:
  `assert(frontier_get_root_hash(outputs_frontier) == outputs_merkle_root)`), :1984-1990 (`run_to_input_mcycle_offset`
  reads the root from `tx[0..DATA)`), :2047-2075 (`input_added` has already cleared `epoch_pair` and `epoch_builder`
  and bumped `input_count` before the input runs), :2485-2488 (a second fail-closed check of the same root in
  `store_checkpoint_files`).
- **Defect:** on a manual rx-accepted fixed point the player reads the root from the transmit buffer, with the length
  taken from the guest's `DATA`, pushes the pending outputs into its frontier, and asserts equality. The transition
  function never interprets that root. When the guest leaves anything else (a stale or garbage value, `DATA` not 32,
  outputs emitted without libcmt), the assert raises inside `input_added`, which has already torn down the epoch
  state, so the player can no longer advance, seal or claim the epoch, and a replay of the input is skipped.
- **Evidence and test:** `bugs/R1-GUESTTOOLS-2/` (`test.lua`, `guest.S`, `link.ld`, `build.sh`). Run `bugs/run.sh
  R1-GUESTTOOLS-2`. A bare-metal guest writes either 32 bytes of `0xAA` or the true root with `DATA = 0`, then yields
  manual rx-accepted. The control variant advances and seals. In both fault variants `input_added(0)` raises "outputs
  Merkle root mismatch", `input_added(1)` then raises "epoch is not open" and `epoch_sealed(2)` raises "sealed input
  count mismatch", while the emulator computes the canonical hash and its logs verify. With only the assert at
  prt.lua:1393 removed, the test passes.
- **Scenario and reachability:** after reading an input, the guest leaves any value other than the true root of its
  outputs at an accepted yield (a buggy application, a corrupted guest-tools tree such as a reset `merkle.dat`, or a
  guest that an input subverted). Only the honest operator diverges: the emulator, the referee and the computation
  hash are all well defined for that state. The honest claim misses its deadlines and is eliminated, and an
  adversary's claim can settle any state. Retries hit the same assert deterministically. The first reviewer noted that
  a correctly designed application never reaches this state; the finding rests on R4 holding at every reachable state,
  as the threat model writes it, not only for correctly designed applications.
- **Possible solution:** do not make claim computation depend on the guest's root. Record the epoch's outputs as
  unprovable (or keep the frontier root alongside the guest value) and keep computing and defending the canonical
  mcycle and uarch claims; refuse only to produce output proofs for that epoch. Make the check in
  `store_checkpoint_files` non-fatal in the same way. Take the length of the root from the fixed 32 bytes, not from
  `DATA` (see R5-DFGUESTOUT-1).
- **Risks:** an application that writes a wrong root silently loses its outputs for that epoch while the honest
  operator keeps defending the canonical state, which is the intended division of responsibility (A5 governs what can
  be extracted). The fix must keep the frontier consistent for later epochs and must not hide a real divergence
  between the player's outputs and the guest's; log it loudly.

---

## R1-PLAYER-1

**Relaunched honest bridge abandons its own claim when an adversary joined that commitment first**

- **Severity:** Critical (on the honest operator's path, an adversary with section 7 capabilities eliminates the
  honest claim).
- **Component and area:** PRT player and bridge (honest operator); the binding of claims to tournaments and its
  derivation from the chain after a restart.
- **Cited rules:** R4 (the honest operator can always respond); A7 (the honest claim must not miss its clocks);
  section 1 completeness failure; section 2 (honest claim, honest operator's path); section 7 (the adversary can
  hold any claim, including the honest one, and race transactions).
- **Location:** `doc/recipes/prt-bridge.lua`:
  - lines 264-273: `joined_by` is true only when some `CommitmentJoined` has `submitter == self.signer.address`;
  - lines 277-299: `update_claims` rebinds a claim only through `bound_child`, `can_join` or `joined_by`;
  - line 335: no honest join is scheduled once `context.joined[claim.root]` exists;
  - lines 188-191 and 360-370: every response job is gated on `holds()`.

### Problem

The honest claim is deterministic, so an adversary can compute it, or copy the honest join's calldata, which is not
bound to the sender, and join the honest commitment from its own account first. The bridge then correctly skips its
own join and defends the claim from memory. After a relaunch, `self.claims` is empty. Once the joining window has
closed, `can_join` is false, there is no `bound_child`, and `joined_by` is false because the adversary submitted the
join. The honest claim is therefore never bound again. `holds()` returns nil, and the bridge schedules none of
`advanceMatch`, `seal*Match`, `winLeafMatch`, `winMatchByTimeout` or `winInnerTournament` for it.

This contradicts the bridge's own specification: `prt-lua-bridge.md` defines `own(x)` as "the player holds
commitment x" with no condition on the submitter, keeps the submitter (`claimer(x)`) for bond recovery only, and
requires ordinary and restarted ticks to derive identical actions. The existing fixture in `prt-bridge-test.lua`
(around lines 976-1084) asserts the defective behavior.

### Evidence and test

- Test: `bugs/R1-PLAYER-1/test.lua`. Run `bugs/run.sh R1-PLAYER-1`.
- It drives the real `refresh` → `observe` → `update_claims` → `jobs` path of `prt-bridge.lua` over a mock chain,
  serving already-decoded logs as `prt-bridge-test.lua` does, and keeps the jobs due at the tip, exactly as `tick()`
  does. It covers two timelines:
  - root tournament: window `[10, 30)`, relaunch at tip 60, honest versus Sybil;
  - uarch child tournament: window `[40, 60)`, relaunch at tip 100, honest versus dishonest.

  Each is checked with the honest signer and with the adversary as submitter of the honest commitment's join.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - the running process answers with `advanceMatch` in every case;
  - the relaunched process answers when the honest signer joined, and schedules nothing when the adversary joined,
    at both levels.
- The prover also checked a fix: a patched copy that binds whenever `context.joined[claim.root]` exists makes the test
  pass.

### Scenario and reachability

1. The adversary joins the honest commitment before the honest player does, at root or child level, paying one bond.
2. The honest process relaunches after the joining window, while the dispute is still running. Disputes last many
   blocks, and the recipe treats relaunch as normal operation:
   - `prt-supervise.sh` restarts on every exit;
   - RPC errors and 60 s timeouts are asserts;
   - `PRT_TEST_RESTART` exercises restarts;
   - the documentation promises restarts need no recovery.
3. The relaunched bridge never answers for its claim. The adversary, which holds the same commitment, lets it time
   out.
4. Its Sybil wins the root, or its dishonest uarch claim wins the child and eliminates the honest mcycle claim in the
   parent match. A wrong epoch state can settle.

No unreachable state and no violation of A1-A7 is needed.

### Possible solution

In `update_claims`, bind the player's claim whenever `holds_parent` holds, the player has not left, and the honest
commitment was joined by anyone: replace `joined_by` with "the tournament has joins", and bind after `build_claim`
only if `context.joined[claim.root]` exists. Keep the submitter check only for bond recovery. Add a fixture that
relaunches after the window with a foreign submitter, at both levels.

### Risks

- Of the issue: after any routine or crash-induced restart, an adversary can make the honest claim time out and
  settle a wrong state. It also collects the bond refund of the honest commitment.
- Of the fix: a relaunched bridge must rebuild claims after windows close (one uarch period for a child). The
  `context.joined[claim.root]` check keeps it from binding in tournaments the honest commitment never entered.
  Bond recovery must stay limited to the bridge's own submissions.

---

## R1-PLAYER-2

**Eight-entry input-boundary cache makes reaching a disputed position cost about n/5 whole inputs**

- **Severity:** Critical (a unit of work on the honest operator's path whose worst-case cost exceeds what the
  deployment was sized for, by a factor that the adversary controls).
- **Component and area:** PRT player (honest operator); the machine cache of input boundaries, and every unit of
  work that replays from it.
- **Cited rules:**
  - R12: "Reaching that position costs at most the mcycles from the nearest retained input boundary, which the
    application's per-input usage bounds."
  - A7: clocks are sized for that cost a bounded number of times per match.
  - R4, section 1 completeness failure, and section 7 (send any number of inputs, steer the dispute to any position).
- **Location:**
  - `doc/recipes/prt.lua:884-885`: `DEFAULT_MACHINE_CACHE_CAPACITY = 8`, shared by the forked and the stored cache
    (`prt.lua:1306-1319`).
  - `doc/recipes/prt.lua:1189-1217`: `machine_cache_methods:consider` evicts entries or doubles `input_gap` when full.
  - `doc/recipes/prt.lua:1944-1949` and `doc/recipes/prt.lua:2021-2043`: `new_machine_pair_at_epoch_input_offset`
    forks the nearest retained entry, and `run_to_epoch_input_offset` replays every intervening whole input.
  - Units that take this path: `collect_mcycle_bundle` (`prt.lua:2101`), `build_uarch_cycle_computation_hash`
    (`prt.lua:2120`), `collect_uarch_cycle_bundle` (`prt.lua:2139`) and `prove_state_transition` (`prt.lua:1845`).
    Each creates a fresh pair, so no replay is shared between them.

### Problem

The player retains at most 8 input boundaries per epoch, spaced about n/5 to n/8 inputs apart for an epoch of n
inputs. Every unit of work starts by forking the nearest retained boundary and replaying every input between it and
the disputed one. The cost of reaching a position is therefore about n/5 times the per-input usage, not the
per-input usage that R12 requires. The adversary chooses n, up to the input limit per epoch (2^24 in this geometry),
and chooses the disputed input.

### Evidence and test

- Test: `bugs/R1-PLAYER-2/test.lua`, with the bare-metal rolling application `guest.S`, `link.ld` and `build.sh`.
  Run `bugs/run.sh R1-PLAYER-2`.
- The guest is correctly designed: it accepts every input after about 1003 mcycles and leaves the empty outputs root
  in the transmit buffer. The test drives the real forked player through `input_added` and `epoch_sealed`, then
  measures the replay each unit performs to reach a chosen input.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - 64 inputs: retained boundaries `{0,9,19,27,39,47,55,63}`; a unit at input 38 replays 11 whole inputs, 11033
    mcycles;
  - 512 inputs: retained boundaries `{0,79,159,223,319,383,447,511}`; a unit at input 318 replays 95 whole inputs,
    95285 mcycles;
  - each of `collect_mcycle_bundle`, `collect_uarch_cycle_bundle` and `prove_state_transition` pays this separately.

  The bound the test asserts is twice the per-input usage, 2006 mcycles.
- A control that swaps in a cache keeping every boundary passes, with no replay. The prover's cache-policy model
  extrapolates the distance to 767 inputs at n = 4096 and 12287 at n = 65536.

### Scenario and reachability

1. The adversary posts many valid inputs into an epoch, each driving a correctly designed application to its
   per-input bound.
2. It posts Sybil claims that agree with the honest claim up to an input just before a retained boundary, and
   diverge there.
3. In each of the logarithmically many matches, the honest player replays about a fifth of the epoch several
   times: once per bottom-level bundle opening, uarch claim build, uarch bundle opening and proof.
4. Clocks sized per A7 for per-input replays are exceeded, the honest player misses a responder deadline or the uarch
   joining window, and its claim is eliminated.

The honest operator cannot decline the inputs or the disputed position. The manual describes this cache as a
bounded-memory design (around `doc/README.md:9679`), but R12 sets the normative bound.

### Possible solution

Make the reach cost independent of the number of inputs:

- retain a boundary at every input, or every constant number of inputs; for example, stored copy-on-write snapshots
  per input, pruned once the epoch settles;
- or let the capacity scale with the input count.

As a constant-factor improvement, reuse one replayed pair across the units requested at the same disputed input. If
the sparse cache is kept, A7 and R12 would have to be restated for (input limit / capacity) times the per-input
usage, which yields impractical clocks.

### Risks

- Of the issue: cheap inputs and Sybil claims force long replays in every match, and the honest claim can be
  eliminated, letting a wrong state and outputs root settle.
- Of the fix: per-input retention costs O(n) storage, which needs copy-on-write or deduplication to be feasible.
  Restored boundaries must hash identically to replayed ones (R2, R9), and must survive crash recovery of the
  stored cache. Sharing a pair between units must not leak one unit's leftover state into another's start.

---

## R1-PLAYER-3

**Player reads the previous epoch's seal with one unpaged `eth_getLogs` and crash-loops once the chain outgrows the
node's range limit**

- **Severity:** Critical (R4 violated on the honest operator's path; no A1-A7 violation or adversary action is
  needed to trigger it).
- **Component and area:** PRT player (honest operator); epoch discovery in the main loop of `prt-player.lua`.
- **Cited rules:** R4 (the honest operator can always respond); A7 (it then loses on time); section 4 (paths that
  carry node data must report errors without terminating the process); section 1 completeness failure.
- **Location:**
  - `doc/recipes/prt-player.lua:165-172` (`get_seal`): `chain:logs(consensus, chain:head(), first_block)`, one
    request over `[deployment block, tip]`;
  - `doc/recipes/prt-player.lua:175-185` (`open_epochs` calls `get_seal(next_epoch - 1)`) and lines 225-229 and
    260-273 (`pass()` runs it first, with no `pcall`);
  - `doc/recipes/prt-cast.lua:152-160` (`methods:logs` asserts on the result).

### Problem

Every `pass()` starts with `open_epochs()`. Once checkpoint N+1 exists, which the listener stores at the seal of
epoch N, `open_epochs` calls `get_seal(N)`. That sends one `eth_getLogs` from the deployment block to the tip and
asserts on the result. Nodes and providers routinely cap the block range of a log filter: Reth defaults to 100000
blocks, about 14 days on mainnet, and hosted providers to 2k-10k. `prt-log-history.lua` exists to page around exactly
that limit, and `prt-epoch.lua` and `prt-bridge.lua` use it; `get_seal` is the only log read that skips it.

Once the deployment is older than the limit, the request is refused. `pass()` raises, the process exits, and
`prt-supervise.sh` relaunches it. The relaunch replays `open_epochs` from `--first-epoch` and dies on the same call,
so no listener polls and no dispute ticks. Raising `--first-epoch` does not help, because it still calls
`get_seal(first_epoch - 1)`. The 60 s socket timeout of `prt-cast` is a second trigger for the same crash.

### Evidence and test

- Test: `bugs/R1-PLAYER-3/test.lua`, with `server.lua` and `vendor/dkjson.lua`. Run `bugs/run.sh R1-PLAYER-3`.
- `server.lua` is a stub JSON-RPC node built on luasocket that refuses filters wider than 1000 blocks with `-32005`.
  `vendor/dkjson.lua` is dkjson 2.11 (MIT), which `prt-ethereum.lua` requires and the test environment lacks.
- The test runs the text of `prt-player.lua` from `get_seal` through `pass` unmodified, against a real `prt-cast`
  client talking HTTP to the stub. It simulates a first launch and two relaunches. As a control, `prt-log-history`
  pages the same range from the same node and finds the `EpochSealed(0)` log.
- Observed, deterministically, by the prover, the reviewer and the orchestrator: all three launches raise
  `query exceeds max block range 1000` in `get_seal` before any listener polls, and the node log shows three refused
  `[0, 5000]` requests.
- Harness checks: with `R1_PLAYER_3_MAX_RANGE=1000000` the same code polls epochs 0 and 1 and passes, and a patched
  copy that routes `get_seal` through `prt-log-history` passes against the limited node.

### Scenario and reachability

No adversary action is needed. As the chain ages past the node's limit, the next seal leaves the honest player
crash-looping exactly when that epoch's dispute begins. It gets at most one tick, right after the seal, and never
answers a bisection. Its claim times out, and an adversary that merely posted a Sybil claim settles that epoch and
every later one. The node is trusted (section 4), but a range limit is its ordinary behavior, which the recipe itself
accommodates elsewhere, so this is a defect in the operator's code, not a misconfiguration.

### Possible solution

Read the previous seal without a full-range query: take it from the previous epoch's listener, which already observes
`EpochSealed` through `prt-log-history`, or keep one `prt-log-history` for the consensus across passes and call its
`get_logs`. Also make `pass()` fail soft on node errors: report them in the status and retry at the next tip instead
of exiting.

### Risks

- Of the issue: any operator whose node or provider caps `eth_getLogs` ranges, which is common, loses every dispute
  from that epoch on, and wrong states and outputs settle.
- Of the fix: the seal source must follow the same finality and reorg policy as the listener (`prt-log-history`
  rewinds), or the player could open an epoch from a seal that is later reorged out. A blanket `pcall` around
  `pass()` must not hide assertions that should stop the player, such as a template mismatch.

---

## R1-PLAYER-5

**Next-epoch inputs run between two ticks of the current dispute, so an input flood delays honest responses past
the clocks**

- **Severity:** Critical, as rated by the reviewer. The hunter and the prover proposed High, on the grounds that
  whether a deadline is missed depends on clock sizes. The reviewer noted that clocks sized only per A7 cover the
  dispute's own costs, not a batch of next-epoch work that the adversary sizes. It is High only in a deployment whose
  allowances deliberately absorb a full next-epoch accumulation per response, which A7 does not require.
- **Component and area:** PRT player (honest operator); scheduling between accumulating the open epoch and
  defending the sealed one.
- **Cited rules:** R4 (the honest operator can always respond in time); A7 and R12 (clocks budget a bounded number of
  per-input costs per match); section 1 completeness failure; section 7 (any number of inputs chosen to maximize cost,
  racing transactions).
- **Location:**
  - `doc/recipes/prt-player.lua:225-245` (`pass()`): polls listeners and ticks bridges in order, on one thread;
  - `doc/recipes/prt-epoch.lua:58-77` (`poll()` runs `input_added` for every newly confirmed input);
  - `doc/recipes/prt.lua:2047-2080` (`input_added` runs the input to its deadline, then stores the epoch state).

### Problem

While epoch N is in dispute, the listener of epoch N+1 is open, because N's seal writes the N+1 checkpoint. Each
`pass()` ticks epoch N's bridge and then lets epoch N+1's listener run every newly confirmed input synchronously,
each to the application's per-input bound, followed by a store and sync. Nothing bounds the work per poll, and
nothing gives the sealed dispute priority. The gap between two consecutive ticks of epoch N's bridge therefore
includes the full cost of the next epoch's newly confirmed inputs, whose count the adversary chooses. Under the
default `finalized` input policy, confirmations arrive in 32-block jumps, so a whole batch lands in one poll; a
`latest` policy still processes a block's worth at once. This contradicts the stated intent in `prt.lua` that "the
next player can accumulate inputs while this player disputes the sealed epoch".

### Evidence and test

- Test: `bugs/R1-PLAYER-5/test.lua`, with the bare-metal application `guest.S`, `link.ld`, `build.sh` and
  `vendor/dkjson.lua` (dkjson 2.11, MIT). Run `bugs/run.sh R1-PLAYER-5`; it takes about 17 s.
- Setup:
  - `pass()` is extracted verbatim from `prt-player.lua` and run over two real `prt-epoch` listeners;
  - epoch 7 is sealed, with a real `prt-bridge` whose honest claim is the responder of a match;
  - epoch 8 is open, with a real stored player and a correctly designed application that accepts each input after
    about 100k mcycles;
  - only the chain is fake: its tip advances one block per 100k mcycles executed, and 32 adversarial inputs finalize
    together at tip 96;
  - the opponent's move is mined at block 97, with the responder deadline at 117.
- Observed, deterministically, by the prover, the reviewer and the orchestrator: epoch 7's bridge ticks at tips 95,
  96 and then 128, after all 32 epoch-8 inputs. Its due `advanceMatch` is never attempted, and the honest claim loses
  by timeout.
- Control (`R1_PLAYER_5_CONTROL=interleave`, a scheduler that ticks epoch 7 after every input): the same bridge
  submits at block 102 and the test passes. The time scale of one block per 100k mcycles is a modelling choice. Real
  applications use about 1e9 mcycles or more per input, far below the 2^48 deadline, and each input also cost about
  0.5 s of wall time in store and sync here.

### Scenario and reachability

1. During epoch N's dispute, the adversary posts many valid inputs to epoch N+1, each driving a correctly designed
   application to its per-input bound.
2. It times its match move right after the batch becomes visible, or just before a uarch joining window closes.
3. The honest process executes the whole batch before its next tick of epoch N, and misses the deadline.
4. The dishonest claim wins epoch N. The attack repeats at every finality jump, at the cost of input gas only.

### Possible solution

Give dispute responses priority and bound accumulation per pass:

- tick every sealed bridge first, then let open listeners process at most one input, or a small time budget, per
  pass, retrying immediately while a backlog remains;
- or run accumulation in a separate process that owns the next epoch's store;
- or check due deadlines between inputs.

A single input then remains the only atomic unit, which R12 budgets.

### Risks

- Of the issue: valid inputs alone let an adversary eliminate the honest claim in any match or uarch joining window.
- Of the fix: deferring accumulation must not starve epoch N+1 before its own joining window. A retry loop must not
  busy-spin or starve chain observation. A multi-process design must keep store and checkpoint writes isolated and
  preserve the crash and restart idempotence of `input_added` and `epoch_sealed`.

---

## R1-REFEREE-1

**A late Sybil re-post of the honest claim cuts the honest claim's clock to one block**

- **Severity:** Critical (rated as a deployed referee: the honest claim is eliminated without any fault of the honest
  operator, and a fabricated final state settles).
- **Component and area:** PRT referee model; joining of mcycle and uarch tournaments, and the clock each claim
  starts with.
- **Cited rules:**
  - A7: sized clocks; the honest claim gets no room to play its match.
  - Section 1 completeness and soundness of the settled state; section 2 (honest claim).
  - Section 7: Sybils, holding any claim including the honest one, racing transactions.
  - The manual's clock rule (around `doc/README.md:10866`): each claim's clock starts with the tournament's
    allowance, less the blocks to "the claim's joining", as in Dave, where a commitment's clock starts at its first
    join. Section 5 makes the manual's tournament normative.
- **Location:**
  - `doc/recipes/prt.lua:229-244` (`partition_claims`);
  - `doc/recipes/game-transport.lua:705-722` (`reply_less` orders responses by connection admission order;
    admission is assigned at `game-transport.lua:548`);
  - `doc/recipes/prt.lua:687-690` (`open_uarch_tournament` uses the same function).

### Problem

`partition_claims` walks the posters in connection admission order, not in posting order. The first poster of a
computation hash in that order creates the merged claim and fixes
`claim.allowance = allowance - (received_at - start_instant)`. Later posters of the same hash, including the honest
player that posted earlier in logical time, are only subscribed. An adversary connection admitted before the honest
player can therefore post the public, deterministic honest computation hash at the last joinable block, and the
honest claim's clock becomes one block. A response is accepted no earlier than one block after its request, and each
turn must arrive before `start + allowance`, so a claim with a one-block clock can never answer `reveal_bisection` or
`seal_divergence`.

### Evidence and test

- Test: `bugs/R1-REFEREE-1/test.lua`, with `scenario.lua`. Run `bugs/run.sh R1-REFEREE-1`.
- `scenario.lua` runs the real referee (`prt.new_referee(prt.new_dapp_contract(...))`) over `game-test-server` and
  `prtu.protocol`, with three in-process players answering through `prtu.answer_event` over synthetic, consistent
  height-62 claims. It records each bracket claim's allowance and the earliest block at which any holder posted it.
  The honest mock answers at the earliest legal block, so no honest implementation could do better. Story files go
  to a temporary directory.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - attack run: the bracket shows the dishonest claim with allowance 3, and the honest claim with allowance 1 although
    first posted at block 1 (posters `sybil-H`, `honest-H`);
  - the honest reveal at block 4 is rejected as late, the dishonest claim wins by timeout, and the run prints
    `SETTLED DISHONEST`;
  - control run, with the second connection re-posting the dishonest claim instead: `SETTLED HONEST`.
- The prover also checked a fix: taking each merged claim's largest allowance over its posters makes the test pass.

### Scenario and reachability

1. Attacker connection A posts dishonest claim D at block 1.
2. Sybil S, admitted before the honest player, schedules the honest claim for block start + allowance - 1. The
   honest player posts the honest claim at block 1.
3. The bracket is `[D, honest]`, and the honest claim's clock is one block.
4. D opens the match. The honest claim cannot answer in time and loses by timeout.
5. D wins, and `wait_for_outputs` extracts outputs from D's fabricated final state.

Only section 7 capabilities are needed: connect early, then post the honest hash late in the joining window. The
honest operator cannot prevent it, and the same attack hits uarch tournaments, where any subscriber of either mcycle
claim may post.

### Possible solution

In `partition_claims`, take a merged claim's clock from its earliest post over all of its posters. For an existing
claim, `claim.allowance = math.max(claim.allowance, allowance - (response.received_at - start_instant))`. To pair in
join order as Dave does, order the bracket by each claim's earliest `received_at`, breaking ties by admission order.
Apply the fix to both levels.

### Risks

- Of the issue: any Sybil can time out the honest claim in every mcycle or uarch tournament, settling a fabricated
  state and its outputs.
- Of the fix: reordering the bracket changes the narration and transcripts that the recipe compares across runs. Ties
  stay deterministic. A later post must never lengthen a clock beyond what the earliest post gives, which taking the
  maximum allowance guarantees.

---

## R1-REFEREE-2

**Output proofs are not range-checked: every output is accepted again at index i - 2^63**

- **Severity:** Critical (rated as a deployed referee: a proof verifier accepts a node at an index the committed tree
  does not hold, and a settled output can be executed twice).
- **Component and area:** PRT referee model; output verification (`game-output.lua`, loaded by `prt.lua`), which
  relies on the emulator's Lua `cartesi.hash-tree` proof checker.
- **Cited rules:**
  - Section 1 soundness failure: "a proof verifier accepts a node that the committed tree does not hold at the
    stated index and height".
  - A5: an output is accepted only as a leaf at height zero and at the output's index of the full-height outputs
    tree.
  - Section 4 (indices in proofs are adversarial), R11 (the referee, not the proof, fixes the index range), and R9
    (two indices must not authenticate the same leaf).
- **Location:**
  - `doc/recipes/game-output.lua:52-61` (`validate_output_response`);
  - `src/cartesi/hash-tree.lua:11-38` (`verify_slice` and `roll_hash_up_tree`);
  - `doc/recipes/prt.lua:771-785` (`wait_for_outputs` deduplicates on the raw `output_index`).

### Problem

`validate_output_response` checks only these things:

- that `output_index == target_address`;
- that the target size is 0 and the root size is 63;
- the settled root and the leaf hash.

It then calls `hash_tree.verify_slice`, which checks sizes, the sibling count and alignment. Its loop reads only bits
0 to 62 of `target_address`. Nothing requires `target_address < 2^63`, so a genuine proof for index `i` also
verifies with bit 63 set, at the Lua integer `i - 2^63`. That value travels intact through the PRT JSON schema
(`ProveOutputResponse.output_index` is "Default"). `wait_for_outputs` deduplicates by
`accepted_output_indices[output_index]`, so the aliased index counts as a new, unexecuted output. A height-63 tree
has no such index. The range check exists in `assert_valid_frontier_proof`, but this path does not use it.

### Evidence and test

- Test: `bugs/R1-REFEREE-2/test.lua`, with `scenario.lua`. Run `bugs/run.sh R1-REFEREE-2`.
- The scenario runs the real referee end to end (`prt.new_referee`, `run_referee`, `run_tournament`,
  `wait_for_outputs`), with `game-output` as verifier, over `game-test-server` and the real `prtu.protocol` JSON
  encoding.
- The settled state is a small synthetic machine that meets A5's extraction preconditions:
  - `iflags_Y = 1`, and `htif_tohost` is a manual yield with the accepted reason;
  - its transmit buffer holds the root of a height-63 frontier with two outputs; output 0 is "withdraw 100 to
    0xa77acc".

  The honest claim is the only claim, and it wins.
- Observed, deterministically, by the prover, the reviewer and the orchestrator: the honest proof of output 0 is
  accepted, then the same data and siblings with `output_index = target_address = -2^63` are accepted too. Output 0
  is reported as accepted twice.
- Control: re-sending the genuine index-0 response is rejected as a duplicate. A patched `game-output.lua` with the
  range check makes the test pass.

### Scenario and reachability

After any settlement whose outputs tree holds an output (any correctly designed application that emits outputs),
anyone can answer `prove_output` (sent to `EVERYONE`) with the public honest proof of output `i` and the index
`i | 1 << 63`. Every output can be accepted under a second index, so an executed-output bitmap keyed by index would
let a withdrawal be paid twice. No guest or emulator misbehavior is needed. The honest player never serves such an
alias; its `prove_output` returns nothing for negative offsets. The verification game's `vg.lua:962-966` has the
same deduplication pattern, outside the PRT scope.

### Possible solution

- In `validate_output_response`, require an integer `output_index` with
  `math.ult(output_index, 1 << cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT)`, a bound taken from the referee's constant.
- Better, fix it centrally in `hash_tree.verify_slice`: when `log2_root_size < 64`, require
  `(target_address >> log2_root_size) == 0`, a logical shift that also rejects negative integers.

### Risks

- Of the issue: any accepted output can be accepted again, by anyone, from public data, for example a voucher or
  withdrawal executed twice.
- Of the fix: a central check in `verify_slice` also applies to other callers, and it must be skipped for
  `log2_root_size == 64` (whole-machine proofs). Honest proofs never carry high bits. The change should be re-tested
  with `prt-test.lua` and the hash-tree tests.

---

## R1-ROBUST-1

**Honest player keeps every tx-output payload of an input in memory, so a guest drives its memory up without bound**

- **Severity:** Critical (unbounded allocation caused by relayed data that the honest operator must process; a unit
  of work whose cost a guest can make larger than what the deployment was sized for).
- **Component and area:** PRT player (honest operator); collection of outputs while an input runs in `input_added`.
- **Cited rules:** R8 (no guest action may cause unbounded host allocation); R12 (bounded cost of a delivery and of
  a part of a claim); R4 and A7; section 1 completeness failure; section 4 (the guest is adversarial after it reads
  an input, and input payloads cannot be declined).
- **Location:**
  - `doc/recipes/prt.lua:1966-1975`: `run_to_input_mcycle_offset` installs `on_yield_automatic`, which appends every
    tx-output payload to `pending_outputs`.
  - `doc/recipes/prt.lua:1369-1379`: `run_to_stop` calls `receive_cmio_request` at every automatic yield, copying up
    to 2 MiB, over JSON-RPC for the forked player.
  - `doc/recipes/prt.lua:1385-1394` (`flush_pending_outputs`) and `doc/recipes/prt.lua:2055-2068` (`input_added`
    always collects outputs).

### Problem

Nothing bounds the number or total size of the outputs the player keeps for an input. The table is released only
when the input reaches a fixed point, or its 2^48-mcycle deadline, and it is discarded anyway if the input is
rejected. A guest never has to rewrite the transmit buffer: one store of `tohost` (automatic yield, tx-output,
length 2 MiB) in a loop costs about 4 mcycles per output. The host pays a 2 MiB copy, base64 encoding and decoding,
and retention for each one, about 0.5 MiB of retained memory per guest mcycle. The claim does not depend on outputs,
which are opaque guest data, yet collecting them sits on the mandatory path of computing the claim.

### Evidence and test

- Test: `bugs/R1-ROBUST-1/test.lua`, with the bare-metal guest `guest.S`, `link.ld` and `build.sh`. Run
  `bugs/run.sh R1-ROBUST-1`; it takes about 4 s.
- It builds a valid template (rx-accepted yield, empty outputs root) and feeds one input to the real forked player
  through `input_added`. Peak RSS is measured through `VmHWM`, reset between runs with `/proc/self/clear_refs`. The
  test checks that the input was processed and rejected.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - control, 0 outputs: no RSS growth;
  - 64 automatic tx-outputs of 2 MiB in 267 guest mcycles, then a rejection: peak RSS grows about 153 MiB.

  The reviewer reran with an aggressive incremental garbage collector and still measured 141 MiB, so the memory is
  retained, not uncollected.
- The prover also checked a fix: keeping only `#output_data` makes the test pass, with 20 MiB of transient growth.

### Scenario and reachability

1. An adversary sends an input that takes over the guest (section 4).
2. The guest loops on full-buffer automatic tx-output yields, then rejects or runs to the deadline.
3. Every honest node processing the input runs out of memory: a 32 GiB host after about 16k outputs, roughly 64k
   mcycles. Alternatively it stalls far beyond the A7 sizing.
4. The input is replayed after a restart, because `input_count` advances only at commit, so the operator can never
   finish its claim. A dishonest claim wins by timeout.

The subverted-guest exclusion of section 8 applies only while R7 and R8 hold, and R8 fails here. Accepted outputs
are also retained again for the whole epoch, in `self.outputs` for the forked player and on disk for the stored
player; that part was not exercised.

### Possible solution

Take output payloads off the mandatory claim path, or bound them:

- do not fetch every payload while computing the claim;
- when collecting, hash each output into an incremental frontier as it arrives, and spill payloads to a capped
  per-input file that is deleted on rejection;
- cap retained bytes and output counts per input and per epoch, degrading to hashes only;
- serve outputs as a separate, declinable task.

### Risks

- Of the issue: a single input can permanently stop every honest Lua PRT validator from finishing the epoch, so a
  dishonest claim settles.
- Of the fix: output frontiers and proofs must stay exactly consistent with the accepted outputs: order, and dropping
  the outputs of rejected inputs. Spilling to disk only moves the exhaustion unless it is capped. Caps must never
  change the computation hash. The crash-recovery ordering of `commit_epoch_state` must still hold.

---

## R1-VERIFIER-1

**Uarch step verifier aborts the process on a relayed log against a fabricated before-state**

- **Severity:** Critical (the referee model, rated as a deployed referee, must process the log). In consumers that
  only use the emulator and may decline an opponent's proof (C API, Lua, JSON-RPC), it is High.
- **Component and area:** emulator, the uarch step interpreter shared by every off-chain verifier
  (`verify_step_uarch` in the C API, Lua, and JSON-RPC); PRT referee model, which calls it to settle uarch matches.
- **Cited rules:**
  - Section 4: logs and proofs are adversarial, and every path that carries them must report errors without
    terminating the process.
  - R10: a verifier must remain memory-safe and bounded on every before-state.
  - R3: a log defect must be rejected.
  - R2: in a `release=yes` build the C++ verifier silently aligns the address instead (see risks).
  - Section 1 completeness and section 7 (Sybils, any computation hash, steering the dispute).
- **Location:**
  - `src/uarch-solidity-compat.hpp:251-254`: `require(condition, message)` is `assert((condition) && (message))`.
  - `src/Makefile:208-219`: the default and packaged build is `relwithdebinfo`, which defines `NDEBUG` only for
    `interpret.cpp`, so the asserts of `uarch-step.cpp` stay live.
  - `src/uarch-step.cpp:38,44,53,70,89,100`: alignment `require`s on addresses that come from the authenticated
    uarch registers, before `uarch-replay-state-access.hpp` can reject the log. `uarch_step` fetches
    `readUint32(a, pc)` at `src/uarch-step.cpp:1101`.
  - `doc/recipes/prt.lua:273` (`validate_state_transition_response` calls `verify_step_uarch`) and
    `doc/recipes/game-transport.lua:950` (the `pcall` meant to contain bad responses).

### Problem

The uarch interpreter checks alignment with `require`, which in C++ is a C `assert`. In the default build that
assert is active. A failed `require` calls `abort()`, which raises `SIGABRT` rather than a C++ exception, so neither
the `try`/`catch` in `cm_verify_step_uarch` nor a Lua `pcall` can contain it. A log of just three authenticated reads
(`uarch_cycle`, `uarch_halt`, `uarch_pc`) checked against a before-state whose `uarch_pc` is 2 mod 4 makes the
verifier abort before it checks that the log is complete. The same happens with the other misaligned accesses that
fabricated uarch registers can produce.

### Evidence and test

- Test: `bugs/R1-VERIFIER-1/test.lua`, with `bugs/R1-VERIFIER-1/child.lua`. Run `bugs/run.sh R1-VERIFIER-1`.
- `child.lua` builds the fabricated before-state with `write_reg` only to obtain consistent proofs (an attacker
  computes the same hashes offline). It then verifies the three-access log:
  - in process, through `cartesi.machine:verify_step_uarch` under `pcall`;
  - through a spawned `cartesi-jsonrpc-machine` server.

  A control run against the honest, aligned before-state gets a normal, caught rejection
  (`log is missing access 4th access`), so the harness is sound.
- Observed on `feature/prt-audit`, deterministically, by the prover, the reviewer and the orchestrator:
  `uarch-solidity-compat.hpp:253: ... Assertion '(condition) && (message)' failed`, exit status 134 inside `pcall`.
  The JSON-RPC server dies as well, and the next request gets "connection refused".

### Scenario and reachability

1. A1 constrains the agreed before-state only in matches against the honest claim. Two Sybil claims can agree on
   any leaf. That holds for an mcycle leaf that becomes a uarch tournament's initial state, and for any intermediate
   leaf of two Sybil uarch claims, including Sybil uarch claims posted under a match of the honest claim (section 7).
2. When their uarch match reaches a leaf, `settle_uarch_state_hash` asks for `prove_state_transition`. One Sybil
   answers with the three-access log against its fabricated before-state.
3. `validate_state_transition_response` calls `verify_step_uarch`, and the referee process aborts.
4. The referee model is a single process serving every tournament. Its death stops the honest claim's matches as
   well, so the honest claim can no longer win or settle. That is a completeness failure caused by relayed data the
   referee must process (section 8, Critical).

The fabricated before-state is not a reachable machine state, but the trigger is relayed data, a log plus a hash
taken from claims, and section 8 classifies crashes from relayed logs by the relayed-data entries. The same log also
kills any node or `cartesi-jsonrpc-machine` server that verifies other parties' uarch proofs. The deployed Solidity
verifier just reverts and is not affected.

### Possible solution

Make the C++ `require` of the shared uarch interpreter throw a catchable exception in every build type, instead of
`assert`. Then every path rejects the log the way Solidity reverts: replay fails verification, the C API returns an
error code, Lua raises an error, and JSON-RPC returns an error response. As defense in depth, the referee model could
verify proofs in a separate process.

### Risks

- Of the issue:
  - Any pair of Sybils can kill the referee model, halting every tournament and settlement.
  - Any node or JSON-RPC server that verifies relayed uarch logs can be killed.
  - In a `release=yes` build, `NDEBUG` disables the assert and the replay aligns the address down
    (`adjust_access`), accepting a transition that Solidity rejects on that before-state (R2). That divergence was
    not exercised, because rebuilding `src/` was out of bounds for the test. On unreachable states alone it would be
    High.
- Of the fix:
  - It touches the interpreter shared with the generated Solidity. Its semantics must stay "revert", and the code
    generator of `machine-solidity-step` must not change.
  - The uarch program and its pristine hash are unaffected, since only the host build of the interpreter changes.

---

## R2-PLAYER-1

**A settled epoch's bridge cancels the next epoch's pending honest transactions through the shared journal**

- **Severity:** Critical (on the honest operator's path, with no adversarial input beyond a dishonest claim, the
  honest operator cancels its own join and moves and misses its deadlines).
- **Component and area:** PRT player and bridge (honest operator); scheduling of transactions when several epochs'
  bridges share one signer and one transaction journal.
- **Cited rules:** R4 (the honest operator can always respond in time); R12 and A7 (sizing assumes the operator does
  not fight itself); section 1 completeness failure; section 2 (honest claim, honest operator's path).
- **Location:**
  - `doc/recipes/prt-player.lua:119-126`: one `transactions` journal for the whole player;
  - `doc/recipes/prt-player.lua:176-219`: every epoch listener gets that journal and the same signer, and listeners
    are never removed;
  - `doc/recipes/prt-player.lua:225-243`: `pass()` ticks every sealed bridge in epoch order, and repeats at once
    while a pass published;
  - `doc/recipes/prt-epoch.lua:19-23`: `poll()` returns the bridge for good once the epoch is sealed;
  - `doc/recipes/prt-bridge.lua:660-681`: `tick()` takes `transactions:pending(signer)`, the newest candidate at the
    account's next nonce whichever epoch signed it, compares it only with its own epoch's due jobs, and otherwise
    calls `cancel()`;
  - `doc/recipes/prt-transactions.lua:91-98` (`pending`), `:128-142` (`fees`, +15%) and `:170-194` (`submit`): the
    `bump_blocks` wait applies only to the same action, and rebroadcast at the fee ceiling only to the same action.

### Problem

Once epoch N has settled, its bridge has no due job, or only bond recovery and cleanup, but it is still ticked first
on every pass. When epoch N+1's bridge publishes the honest `joinTournament`, epoch N's bridge sees a pending
candidate at the shared nonce that matches none of its own jobs, and replaces it with a self-transfer cancel at
+15% fees. Epoch N+1's bridge then sees its job obsolete and replaces the cancel, and so on, because each change of
action is published at once. They alternate until the fee ceiling, and the bridge that hits the ceiling can no longer
replace the other's transaction. Whichever was published last owns the nonce. Which one that is depends on the parity
of the number of bumps to the ceiling, set by the base fee and the limits, so it repeats at every nonce.

### Evidence and test

- Test: `bugs/R2-PLAYER-1/test.lua`, with `vendor/dkjson.lua` (dkjson 2.11, MIT). Run `bugs/run.sh R2-PLAYER-1`;
  it takes under 1 s.
- It runs the real `prt-transactions` journal and the real bridge `tick`, `attempt` and `cancel` paths, overriding
  only each bridge's `observe`, `jobs` and `prepare`, as `prt-bridge-test.lua` does. The fake node holds one
  transaction per nonce, applies geth's 10% replacement rule, and mines once per block. The pass loop matches
  `prt-player.lua`.
- Observed, deterministically, by the prover, the reviewer and the orchestrator, at a 10 gwei base fee with default
  limits:
  - control, epoch 1's bridge alone: the join is mined at block 101, with its window closing at 111;
  - with epoch 0 settled and epoch 1: each of blocks 101-110 sees 12 publications alternating join and cancel; the
    cancel wins at a 97.7 gwei max fee, and the join is blocked at "fee ceiling";
  - 10 of 10 mined transactions are cancels, and the join is never mined in its window;
  - a base-fee sweep from 1 to 40 gwei loses the join at 19 of 40 values.

### Scenario and reachability

The documented `prt-player.lua` loop reaches this from epoch 1 on, with the honest strategy, on any chain that does
not mine each transaction the instant it arrives. `prt-demo.sh` runs Anvil with automine, which hides it. The honest
claim never joins epoch N+1's tournament, so a dishonest claim wins unopposed. The same race hits every
deadline-bound move (`advanceMatch`, seals, `winLeafMatch`, `winInnerTournament`), so the honest claim can also be
eliminated by timeout. Where a block arrives mid-race, the outcome depends on timing rather than parity, but every
move still races its own older-epoch bridge, with fees driven to the ceiling.

### Possible solution

Decide nonce ownership per signer, not per bridge:

- either one arbiter gathers every bridge's due jobs, picks one by the existing earliest-expiry order, and is the
  only one that cancels;
- or, minimally, `tick()` treats a candidate whose `context.epoch` or `context.root` belongs to another bridge as
  foreign, and neither cancels nor replaces it.

Stop ticking listeners whose epoch is settled and have no remaining jobs, and optionally apply the `bump_blocks` wait
to every replacement.

### Risks

- Of the issue: the honest claim misses joins and moves, a wrong state settles, and every nonce is pushed to the fee
  ceiling, draining the signer.
- Of the fix: treating foreign candidates as untouchable can strand an obsolete one, or starve a more urgent
  older-epoch job behind a newer pending transaction. An arbiter must rank deadlines across epochs and survive
  restarts; the journal already persists `context.epoch` and `context.root`. Dropping settled listeners must not lose
  pending bond recovery or cleanup. The journal's reorg-safety and nonce invariants must be kept.

---

## R2-REFEREE-1

**At a sealed uarch leaf, the honest claim gets only the opponent's clock to prove, with no timeout win**

- **Severity:** Critical (rated as a deployed referee: a Sybil with a short clock eliminates the honest uarch claim,
  and a second Sybil then decides the enclosing mcycle match for the dishonest claim).
- **Component and area:** PRT referee model; settlement of a sealed uarch leaf (the leaf race).
- **Cited rules:**
  - A7: the honest claim's window must be its own A7-sized clock, not one the adversary chooses.
  - A1: the uarch winner's last leaf decides the enclosing match.
  - R4, and section 1 completeness failure.
  - Section 5: this disagrees with deployed Dave and is outside the manual's listed simplifications, so it is a
    defect.
  - Section 7: Sybils, and the timing of joins and responses.
- **Location:**
  - `doc/recipes/prt.lua:395-438` (`settle_uarch_state_hash`): `proof_deadline = min(deadline_one, deadline_two)`
    at lines 402-405, `"late state transition proof"` at line 410, and elimination of both claims without a timeout
    win at lines 422-433;
  - `doc/recipes/prt.lua:567-583` (`settle_divergence` returns 0 when both are eliminated);
  - `doc/recipes/prt.lua:229-244` (late joiners get `allowance - delay`) and `doc/recipes/prt.lua:344-349`
    (`charge_turn_time` lets a claim drain its own clock).
  - Contrast `doc/recipes/prt-bridge.lua:342-373` and `doc/recipes/prt-lua-bridge.md:352`, which follow Dave: "Holder
    of the longer clock may win by timeout ... Timeout in [min, max)".

### Problem

At a sealed uarch leaf, the model starts both clocks at the seal and accepts a transition proof only before
`min(deadline_one, deadline_two)`. If none arrives, it waits until the later deadline and eliminates both claims; no
timeout win is ever offered, and the manual repeats this ("Nobody may claim a timeout win at a sealed leaf",
`doc/README.md:10910`). The honest claim's window to produce the leaf proof is therefore bounded by the opponent's
remaining clock, which the adversary controls in two ways:

- by joining the uarch tournament late, because `partition_claims` gives a late joiner the allowance minus its delay;
- by answering its own turns late, because `charge_turn_time` drains its clock, down to the response budget plus one.

In deployed Dave (`MatchClocks.classifyTimeoutAt`), the claim with time left wins by timeout after the earlier
deadline, so the honest claim always has its own clock. The manual's list of simplifications (around
`doc/README.md:11179`) does not cover the leaf race.

### Evidence and test

- Test: `bugs/R2-REFEREE-1/test.lua`, with `scenario.lua`. Run `bugs/run.sh R2-REFEREE-1`; it takes about 0.4 s.
- It runs the real `prt.new_referee` over `game-test-server` and `prtu.protocol`, with mcycle and uarch heights of 3,
  a maximum allowance of 8, and the real first uarch step of a 4 KiB machine as the disputed transition. Players
  connect in the order honest, S1, S2, so the uarch bracket is H versus S1, with S2 unmatched. S2 ends at the same
  dishonest final state under a different computation hash. The harness only observes; it does not change referee
  logic.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - attack, late join: S1 joins 5 blocks late with a 2-block clock, and the leaf is sealed with H at 6 and S1 at 2.
    The honest proof arrives 2 blocks after the seal, within its own clock, and is rejected as late. H and S1 are
    eliminated, S2 wins the uarch tournament, and the dishonest mcycle claim wins the epoch.
  - drain, with response budget 0: the honest player answers at the earliest legal block, and S1 drains its clock to
    1 on its seal. The honest proof at seal + 1 is rejected, with the same outcome.
  - a Lua reimplementation of Dave's `classifyTimeoutAt` on the same clocks gives the honest side the win in both
    modes;
  - control: an honest proof one block after the seal under stock clocks is accepted, and the honest claim wins.
- The prover also checked a fix: adding Dave's timeout-win window to a copy of `prt.lua` makes the test pass.

### Scenario and reachability

1. An mcycle match between the honest and a dishonest claim reaches a uarch tournament. The honest player posts its
   uarch claim early.
2. The adversary posts two uarch claims ending at the dishonest state: S1 late, with just enough clock to bisect,
   and S2 at any time.
3. S1 bisects to the leaf, and the leaf race starts with S1's short clock.
4. The honest operator must run its machine to the disputed uarch position and log the step within that short clock,
   whatever its own A7-sized clock is.
5. If it needs more, both H and S1 are eliminated, S2 wins the uarch tournament, and the honest mcycle claim loses.

Every step uses section 7 capabilities only. The demo's toy constants (allowance 4, budget equal to allowance) and
logical time, in which the honest player always answers at the next block, keep the stock run from tripping. But
clock values are not normative (section 5), and the drain mode needs no honest latency at all. A smarter player could
precompute the leaf proof during its last bisection turn, but its transaction would still have to land within the
adversary's leftover clock, which is the dependence Dave's rule removes.

### Possible solution

Adopt Dave's leaf-race rule in `settle_uarch_state_hash`:

- accept a valid proof before the earlier deadline, as now;
- in `[min, max)` with distinct deadlines, let the holders of the longer-clock claim win by timeout;
- allow elimination only from the later deadline, or right away when the deadlines are equal.

An equivalent alternative accepts a proof from claim i's holders while `received_at < deadline_i`. Update the
manual's leaf-race paragraph to match.

### Risks

- Of the issue: in any deployment that uses the model's rule, short-clock Sybils eliminate the honest uarch claim,
  and a wrong epoch state can settle. The model also mispredicts the bridge's and Dave's behavior.
- Of the fix: transcripts and narration change, so `prt-test.lua` and the manual's story need updating. The
  equal-deadline case must still eliminate both claims. The timeout window must use the same deadline convention as
  `settle_timeout`, and the winner's returned clock must mirror Dave's.

---

## R3-PLAYER-1

**Honest player cannot sign a `winLeafMatch` proof for inputs of about 37 KB or more, because calldata goes to `cast`
as one shell argument**

- **Severity:** Critical (a crash caused by relayed data the honest operator must process, which eliminates the
  honest claim).
- **Component and area:** PRT player and bridge (honest operator); signing transactions through the `cast`
  command-line tool.
- **Cited rules:** R4 (the honest operator must produce, and therefore submit, every requested proof); R12 (every
  honest proof fits the chain's per-transaction limits and must be submittable); A7; section 1 completeness failure;
  section 4 (paths carrying relayed data must report errors without terminating the process).
- **Location:**
  - `doc/recipes/prt-cast.lua:13-25`: `M.run` joins the quoted arguments into one string and asserts on
    `io.popen`, which runs `/bin/sh -c <string>`.
  - `doc/recipes/prt-cast.lua:174-202`: `methods:sign` passes `transaction.data` to `cast mktx`, and `verify_signed`
    passes the raw transaction to `cast decode-transaction`.
  - `doc/recipes/prt-bridge.lua:472-482`: the `winLeafMatch` arguments include `eth.transition_proof`.
  - `doc/recipes/prt-ethereum.lua:152-172`: at mcycle 0 and uarch cycle 0, the proof embeds the 8-byte length and
    the whole input.
  - `doc/recipes/prt-transactions.lua:262` (`submit` calls `chain:sign`) and `doc/recipes/prt-player.lua:253-273`
    (`pass` runs with no `pcall`).

### Problem

Linux caps a single argument at `MAX_ARG_STRLEN` = 131072 bytes, and the whole quoted command is one argument of
`sh -c`. The proof of the transition at the start of an input slot embeds the entire input, plus about 28.5 KB of
delivery and step logs, and the calldata is passed as hex. From an input of about 36.9 KB on, the command exceeds the
cap. `execve` fails with `E2BIG`, `io.popen` returns nil, and the assert raises "Argument list too long". Nothing on
`tick` → `attempt` → `submit` → `sign`, or in `pass()`, catches it, so the player exits. `prt-supervise.sh` relaunches
it into the same failure on every pass while the job is due. The transaction itself is fine for the chain: the 40 KB
case is about 68.7 KB of calldata, under geth's 128 KiB pool limit, and about 1.1M calldata gas.

### Evidence and test

- Test: `bugs/R3-PLAYER-1/test.lua`, with the bare-metal rolling guest under `guest/` (built at test time),
  `fakebin/cast` (a Lua stand-in for the `cast` binary that logs each run), and `vendor/dkjson.lua` (dkjson 2.11, MIT).
  Run `bugs/run.sh R3-PLAYER-1`; it takes about 1.4 s.
- It stores a valid template and runs the honest `prt.new_forked_player` on a 1,024-byte and a 40,000-byte input. For
  each, it builds exactly what `prt-bridge` prepares for the delivery leaf (`prove_state_transition`, then
  `eth.transition_proof`), and checks that `eth.verify_transition` from the agreed leaf yields the honest uarch leaf 0.
  It then encodes `winLeafMatch` calldata and submits it through the real `prt-transactions` journal and the real
  `prt-cast` sign path. Only the node's JSON-RPC and the `cast` binary are stubbed, and the test puts `fakebin` first
  on `PATH`.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - 1,024-byte input: a 29,672-byte proof, 59,786 hex characters of calldata, signed and published;
  - 40,000-byte input: a 68,456-byte proof, 137,354 hex characters, natively valid, and `prt-cast.lua:19: ... Argument
    list too long`; the stub `cast` never ran.
- The reviewer independently confirmed the OS limit: `io.popen` of a command of 131,072 bytes or more fails, and one of
  131,000 bytes succeeds.
- Harness note: the forked player's `cartesi-jsonrpc-machine` children can outlive the test. Piping its output into a
  pager can therefore appear to hang; redirect to a file instead.

### Scenario and reachability

1. The adversary sends a correctly designed application an input of about 40 KB. That is within the 64 KiB InputBox
   cap, the 2 MiB receive buffer and Ethereum's limits.
2. It posts a Sybil mcycle claim that diverges in that input's first period, then a uarch claim that diverges at uarch
   leaf 0, and steers the bisection there (section 7). That leaf's form is delivery followed by a uarch step.
3. At the sealed leaf, the honest bridge prepares a valid `winLeafMatch` and crashes while signing it, on every
   relaunch.
4. The honest claim never proves its leaf and is eliminated. The crash loop also blocks every other job of every
   epoch, so a dishonest claim can settle a state the transition function does not define.

The defect does not depend on the Dave contracts: the calldata holds at least the proof bytes, whatever the ABI.

### Possible solution

Never pass calldata or raw transactions through `argv` or a shell:

- build and RLP-encode the EIP-1559 transaction in Lua, and sign only its 32-byte digest, for example with
  `cast wallet sign --no-hash` or an in-process signer;
- or use a signer reached over JSON-RPC or stdin;
- or pass data through a file or stdin without `sh -c`.

Also wrap each job's `prepare` and `submit` in a `pcall` that reports and continues, and check sizes against chain
limits rather than OS limits.

### Risks

- Of the issue: one 40 KB input plus Sybil claims eliminates the honest claim, and the crash loop starves every other
  job.
- Of the fix: reimplementing transaction encoding and signing can introduce signature or nonce bugs, so the
  independent `verify_signed` check must be kept without going through `argv`. Digest-only signing must apply only to
  digests the operator computed itself. Catching errors per job must still report persistent failures and keep the
  journal's nonce invariants.

---

## R4-VARABORT-1

**`cartesi-machine` CLI cannot compute claims when a rejected input leaves DATA above the transmit-buffer size**

- **Severity:** Critical (R4 violated at a reachable state on the honest operator's path; a crash caused by
  relayed data the honest operator must process).
- **Component and area:** emulator; the `cartesi-machine` CLI in cmio mode, including its mcycle and uarch
  computation-hash builders, which the manual presents as the tool that computes the claims the dispute bisects
  (`doc/README.md:2555-2590`, `10310-10316`).
- **Cited rules:** R4; R2 (the CLI builders must agree with the machine API, which hashes this state); section 1
  completeness failure; section 2 (reachable state, correctly designed application, honest operator's path); section 4
  (input payloads cannot be declined); section 8 Critical.
- **Location:**
  - `src/cartesi-machine.lua:3293-3295`: `get_and_print_yield` calls `machine:receive_cmio_request()` with no guard.
  - `src/cartesi-machine.lua:4653-4656` (`run_advance_state_input`, at every manual-yield fixed point, before it checks
    for a rejection) and `src/cartesi-machine.lua:4504-4505` (`run_to_stop`, at every automatic yield).
  - `src/machine.cpp:1992-1995`: `receive_cmio_request` throws "CMIO request data is too large" when DATA exceeds the
    2 MiB transmit buffer on any yield that is not a progress report.
- **Related:** R1-GUESTTOOLS-1 is the same failure in the PRT player. Both come from the throwing
  `receive_cmio_request`. The fix proposed there lives in `prt.lua` and leaves the CLI broken, so this is a separate
  defect, unless a single change in the C++ API fixes both.

### Problem

The CLI reads the transmit buffer at every yield. On an rx-rejected manual yield with DATA above 2 MiB, which the
manual allows ("On reject, DATA is ignored", `doc/README.md:7591`), `receive_cmio_request` throws. Nothing catches the
error, so the run exits 1 before the computation hash is completed or stored. The machine API handles the state
normally: it hashes it, and the rejection reverts. Automatic tx-output and tx-report yields with oversized DATA fail
the same way.

### Evidence and test

- Test: `bugs/R4-VARABORT-1/test.lua`, with `yield.S`, `link.ld` and `build.sh` (the guest of R1-GUESTTOOLS-1, built
  at test time). Run `bugs/run.sh R4-VARABORT-1`; it takes about 0.7 s.
- It builds two valid templates that differ only in the rejected yield's DATA (`0x10` and `0x200001`), and runs
  `src/cartesi-machine.lua --remote-spawn ... --load=<template> --cmio-advance-state=...` in four modes:
  - `--mcycle-computation-hash`;
  - `--uarch-cycle-computation-hash` for period 0;
  - the same for period 1;
  - plain cmio advance.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - control (DATA `0x10`): all four modes exit 0, and the hashing modes write 32-byte hash files;
  - oversized (DATA `0x200001`): the machine API reaches the rejected yield and hashes it, but all four modes exit 1
    with `cartesi-machine.lua:3294: CMIO request data is too large`, and no mcycle computation hash is written.

### Scenario and reachability

An attacker sends an advance-state input that a correctly designed application rejects with a large DATA. That is
allowed by the manual, and possible with `machine-guest-tools`' own `yield` utility, which passes any data argument.
An operator computing its claim with the documented CLI can produce neither the mcycle claim nor the uarch claim for
any period after the rejection. Restarts replay the same input and fail again, so the operator misses its clocks and a
dishonest claim can settle.

### Possible solution

In the CLI, read `htif_tohost_cmd`, `htif_tohost_reason` and `htif_tohost_data` as registers. Read the transmit buffer
only where its payload is used: the first 32 bytes for the outputs root on rx-accepted, and payloads on tx-output and
tx-report. Skip rejections and unknown reasons, and apply a deterministic, non-raising policy to oversized output and
report yields. Alternatively, make `machine::receive_cmio_request` report oversized DATA without throwing, which fixes
R1-GUESTTOOLS-1 too.

### Risks

- Of the issue: one on-chain input stops the documented claim-computing tool for the whole epoch.
- Of the fix: the stored outputs root must match the on-chain extraction (A5). Changing `receive_cmio_request` is a
  host API change other callers may rely on; it does not change the transition function, but it should be versioned.

---

## R4-VARRANGE-1

**libcmt ABI decoder omits a bounds check on a decoded dynamic offset**

- **Severity:** Critical (`AUDIT.md`: an input makes an application that uses these tools as documented commit a
  wrong output). Confirmed by an independent disproving reviewer and reproduced by the orchestrator.
- **Component and area:** `machine-guest-tools` v0.18.0; libcmt's public ABI decoder for dynamic `bytes`
  (`cmt_abi_peek_bytes_d` / `cmt_abi_get_bytes_d`), documented by `abi.h` for decoding an input payload.
- **Cited rules:** section 1 goal; section 2 (correctly designed application); section 4; section 7; the `AUDIT.md`
  rule for `machine-guest-tools`.
- **Location:** `machine-guest-tools` `sys-utils/libcmt/src/abi.c:288-304` and `sys-utils/libcmt/src/buf.c:34-55`.
- **Defect:** a dynamic offset taken from the input is not bounded against the frame before it is used to locate the
  `bytes` field, so an out-of-range offset is accepted instead of rejected.
- **Evidence and test:** `bugs/R4-VARRANGE-1/` (`test.sh`, `app.c`, `mkinputs.lua`, `check.lua`; boot artifacts are
  generated under the gitignored `build/`). Run `bugs/run.sh R4-VARRANGE-1`. A correctly designed guest application
  that decodes its payload with the documented API is driven on the pinned kernel and rootfs; a crafted input makes
  it commit an output whose bytes are not in the payload (which enters the outputs Merkle root), and another crafted
  input halts the machine. A patched libcmt with the bounds check rejects both and the test passes.
- **Possible solution:** reject a decoded offset or length that exceeds the remaining buffer before forming a
  pointer, and compare lengths rather than pointers in the buffer-split helper; add unit tests and cut a new
  `machine-guest-tools` release (applications must rebuild, as libcmt is statically linked).

**Write-up note:** a safety classifier stopped the orchestrator's detailed draft of this entry three times. The
finding is a standard missing-bounds-check defect in an open-source parsing library; this is a factual summary, and
the full reproduction is the committed test. The audit report flags it as confirmed with its detailed write-up
withheld.

---

## R5-DFGUESTOUT-1

**Player and CLI read the outputs root using the guest's `tohost` DATA as its length, so a valid template with DATA
other than 32 crashes both on an oversized no-op input**

- **Severity:** Critical, as rated by the reviewer (R4 violated at a reachable state; a crash caused by relayed data
  the honest operator must process). Reachability depends on a contradiction in the manual, described below, which
  narrows the set of exposed templates to guests that do not yield with DATA = 32.
- **Component and area:** PRT player (honest operator) and the emulator's `cartesi-machine` CLI; reading the outputs
  Merkle root at an accepted yield.
- **Cited rules:** R4; R2; A5 (the referee takes the root as the fixed first 32-byte word of the transmit buffer and
  ignores DATA); section 2 (valid template, reachable state, correctly designed application); section 4; section 1
  completeness failure; section 8 Critical.
- **Location:**
  - `doc/recipes/prt.lua:956-959`, `1385-1394` (`flush_pending_outputs` asserts the frontier root equals the string
    read), `1983-1990` (`run_to_input_mcycle_offset`) and `2055-2068` (`input_added`);
  - `src/cartesi-machine.lua:3626-3651` (`flush_pending_outputs` asserts `#data == HASH_SIZE`), `4560-4568`,
    `4655-4662`;
  - `src/machine.cpp:1992-2002`: `receive_cmio_request` returns as many bytes as the guest wrote in the DATA field.

### Problem

Both claim computers take the outputs root from `receive_cmio_request`, which returns DATA bytes of the transmit
buffer, with DATA chosen by the guest. The referee model (`game-output.lua`) reads a fixed 32-byte word and ignores
DATA. When an advance-state input is a provable no-op (it is larger than the receive buffer), the machine stays at
the template's own accepted yield, and both hosts re-read the root with the template's DATA. If that DATA is not 32,
the player fails with "outputs Merkle root mismatch" and the CLI with "expected outputs Merkle root in tx buffer",
although the root in the state is correct.

The manual contradicts itself on DATA at an accepted yield. Its yield section says DATA "carries the length of that
hash in bytes" (around `doc/README.md:7587`), while its low-level guest loop initializes `length = 0` for the first
accepted yield and passes it as DATA (around line 7614). `assert_rolling_template` and the section 2 valid-template
conditions do not constrain DATA. Templates built on libcmt use DATA = 32 and are not affected.

### Evidence and test

- Test: `bugs/R5-DFGUESTOUT-1/test.lua`, with the bare-metal guest `guest.S`, `link.ld` and `build.sh` (built at test
  time). Run `bugs/run.sh R5-DFGUESTOUT-1`.
- The guest follows the manual's low-level loop. Its first accepted yield has DATA = 0 (the control uses 32), and
  later accepts use 32. The test stores two templates and delivers an input of `(1 << 21) + 1` bytes.
- Harness checks that pass before the subject cases run: on both templates the oversized input leaves the root hash
  unchanged, its delivery log verifies, and the machine stays at the accepted yield; the DATA = 32 template works in
  both the player and the CLI; the DATA = 0 template works in the player with a small input.
- Observed, deterministically, by the prover, the reviewer and the orchestrator, on the DATA = 0 template: the player
  raises `prt.lua:1393: outputs Merkle root mismatch`, and the CLI aborts at `cartesi-machine.lua:3651` with no
  computation hash. The CLI case needs `--remote-spawn --remote-address=127.0.0.1:0 --remote-shutdown`.
- Fix check: with `prt.lua` reading `read_memory(AR_CMIO_TX_BUFFER_START, 32)`, the player part passes.

### Scenario and reachability

1. The operator defends a valid template whose guest follows the manual's low-level loop, so DATA = 0.
2. An adversary posts, as an early input, one larger than the 2 MiB receive buffer (section 7 allows this). The
   delivery is a correct, provable no-op.
3. `input_added` raises before committing, and a relaunch replays the same input and fails again. The documented CLI
   fails the same way, so neither claim computer can defend the epoch, and a dishonest claim can win by timeout.

Rejected inputs revert to the template, so the exposure persists until some input is accepted.

### Possible solution

Read the root exactly as the referee does: a fixed 32 bytes from the start of the transmit buffer whenever the machine
waits at an accepted yield, ignoring DATA. Apply it in `prt.lua` (`run_to_input_mcycle_offset`,
`flush_pending_outputs`) and in the CLI (`flush_pending_outputs`, the saved-root and accept-state-proof paths, and
`assert_rolling_template`). Keep the frontier-versus-root self-check so a real mismatch is still detected. Optionally
make the manual's two passages agree.

### Risks

- Of the issue: one permissionless input eliminates the honest claim for any valid template whose guest does not use
  libcmt's DATA = 32 convention.
- Of the fix: the root the CLI saves would change for guests that yield accepted with DATA other than 32, which now
  matches the referee, so scripts that compare CLI artifacts may need updating.

---

## R5-DFGUESTOUT-2

**`cartesi-machine` CLI keeps every tx-output payload in memory and writes every report or rejected output to its own
file by default**

- **Severity:** Critical (unbounded allocation caused by a guest the honest operator must run to compute its claim;
  the same basis on which the player-side twin R1-ROBUST-1 was confirmed).
- **Component and area:** emulator; the `cartesi-machine` CLI in cmio mode, including the mcycle and uarch
  computation-hash modes that the manual presents as the tool that computes claims.
- **Cited rules:** R8 (no guest action may cause unbounded host allocation); R12; R4; A7; section 1 completeness
  failure; section 2 (honest operator's path); section 4; section 8 Critical.
- **Location:** `src/cartesi-machine.lua:4626-4633` and `4498-4509` (`on_yield_automatic` appends every tx-output
  payload to `advance.pending_outputs`), `3626-3667` (`flush_pending_outputs`), `3318-3330` (saving reports and
  rejected outputs), `2056-2063` (the default file patterns).
- **Related:** R1-ROBUST-1 is the same behavior in the PRT player (`prt.lua`). The location and the fix differ, as
  with R1-GUESTTOOLS-1 and R4-VARABORT-1.

### Problem

For every automatic tx-output yield the CLI copies the whole payload (up to the 2 MiB transmit buffer) into
`pending_outputs`, which is cleared only when the input reaches its fixed point or is rejected. A guest can re-yield
the full buffer every few mcycles without rewriting it, so retained host memory grows by about 0.5 MiB per guest
mcycle. In addition, by default each report or rejected output is written to its own file. No option disables the
in-memory retention. The computation hash does not depend on any of it.

### Evidence and test

- Test: `bugs/R5-DFGUESTOUT-2/test.lua`, with the bare-metal guest `guest.S`, `link.ld` and `build.sh` (built at test
  time). Run `bugs/run.sh R5-DFGUESTOUT-2`; it takes about 13 s.
- It builds a valid template and runs the real CLI (`--remote-spawn`, `--mcycle-computation-hash`) on a rejected
  input, measuring the CLI's own peak RSS. It checks that a 32-byte hash is written and that the hash is the same with
  and without report files.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - memory, with every output file disabled: peak RSS 17 MiB with no outputs, and 176-179 MiB for 64 tx-outputs of
    2 MiB, a growth of about 160 MiB;
  - disk, with the default patterns: 0 MiB with no reports, and 128 MiB for 64 reports.
- A patched copy that keeps only `keccak256(data)` per output and does not save reports makes the test pass, with
  20 MiB of growth and 0 MiB of disk.

### Scenario and reachability

An input that takes over the guest (section 4) loops on full-buffer automatic yields. The operator running the
documented CLI to compute its claim runs out of memory or disk before writing the computation hash, and a restart
replays the same input. A 32 GiB host is exhausted after about 64k mcycles, far below any per-input limit, so no
deployment can be sized for it. The disk half can be avoided by disabling the file patterns; the memory half cannot.

### Possible solution

Process each tx-output as it arrives: compute its keccak256 once and keep only the hash and position. Write payloads
to a temporary per-input file only when an output pattern is set, and rename it on acceptance; drop it on rejection.
Add a length-only query so the payload need not be copied when no pattern is set, and make per-file report output
opt-in in the computation-hash modes.

### Risks

- Of the issue: one input can stop the documented claim computer before it writes the hash.
- Of the fix: keeping hashes still grows linearly, at about 8 bytes per guest mcycle, which is far below today's
  growth. Early writes followed by renames can leave stray temporary files if the run is interrupted. The root check
  against the frontier must be preserved.

---

## R5-DFINPUT-1

**libcmt `cmt_abi_get_bool` returns success for ABI words that are not a valid bool**

- **Severity:** Critical (`AUDIT.md`: an input makes an application that uses these tools as documented commit a
  wrong output). Confirmed by an independent disproving reviewer and reproduced by the orchestrator.
- **Component and area:** `machine-guest-tools` v0.18.0; libcmt's public ABI decoder for `bool`.
- **Cited rules:** section 2 (correctly designed application); section 4 (input senders send any bytes); section 7;
  the `AUDIT.md` rule for `machine-guest-tools`.
- **Location:** `machine-guest-tools` `sys-utils/libcmt/src/abi.c:264-272` (`cmt_abi_get_bool`) and
  `abi.c:89-102` (`cmt_abi_decode_uint_nr`, which checks only the 31 leading bytes). The documented return codes in
  `include/libcmt/abi.h:411-431` are 0 and `-ENOBUFS` only.
- **Defect:** the decoder copies the last byte of the 32-byte word into the bool's storage unchanged, so a word whose
  last byte is above 1 returns success and leaves a bool object that is neither 0 nor 1. libcmt's own encoder never
  writes such a word, and Solidity's decoder rejects it.
- **Evidence and test:** `bugs/R5-DFINPUT-1/` (`test.lua`, `app.c`, `build.sh`; boot artifacts are generated under
  the gitignored `build/`). Run `bugs/run.sh R5-DFINPUT-1`. A guest application that decodes a bool payload with the
  documented API and checks the return code is built against the live pinned libcmt and run on the pinned kernel and
  rootfs. A control input behaves correctly; an input with a non-0/1 word is accepted, and the application commits
  an output its logic cannot produce for any valid bool. With the decoder fixed in a patched copy, the input is
  rejected and the test passes.
- **Possible solution:** decode into a `uint8_t`, reject a word with nonzero leading bytes or a last byte above 1
  (for example with `-EDOM`), and set the result from the checked byte. Document the new return code and add tests
  for last bytes `0x02` and `0xff`. Applications must be rebuilt, as libcmt is statically linked.
- **Risks:** a deployed application that decodes a bool from its input can be made to commit an output its logic
  would never produce, and every honest validator computes the same result. The fix is local and rejects only input
  that was never a valid ABI bool.

---

## R7-FPUARCH-1

**An interrupted mark-dirty leaves a dirty page under clean ancestors in a shared stored machine, so after a reload
the page is never re-hashed and the root hash goes stale**

- **Severity:** Critical, as rated by the reviewer (R9 violated on the honest operator's path). The trigger is a
  process death inside a window of a few instructions, not an adversary action. The hunter and the prover noted that
  a downgrade to High is arguable. The reviewer kept Critical because section 8 has no probability-based downgrade and
  R9 names "interrupted or failed updates, and every snapshot the emulator itself writes" explicitly.
- **Component and area:** emulator; the dirty-page tree and the persisted hash tree of a stored machine
  (`SHARING_ALL`), as used by the stored PRT player.
- **Cited rules:** R9 (a persisted hash must equal the root of the actual contents, after interrupted updates and for
  every snapshot the emulator writes); R2 (persisting and restoring must agree with an uninterrupted run); R4; section
  1 completeness failure; section 2 (storing and reloading the machine is on the honest operator's path).
- **Location:**
  - `src/dirty-page-tree.hpp:327-335` (`do_mark_dirty_leaf_position_and_up`): it stores the leaf first and then walks
    up, returning early at an already-dirty node.
  - `src/dirty-page-tree.hpp:254-289` (`up_then_down`, `down`): they descend only through dirty ancestors.
  - `src/i-dirty-page-tree.hpp:99-107` (`dirty_iterator`).
  - `src/memory-address-range.cpp:73-79`: a shared `.dpt` file is trusted on load unless pages are marked dirty.
  - `src/machine.cpp:1631-1640`: every hash-tree update marks the write-TLB pages and the always-dirty pages.

### Problem

Under `SHARING_ALL`, the dirty-page tree is a `MAP_SHARED` mapping of `<dir>/<range>.dpt`, and the next load trusts it.
If the process dies after the leaf byte is stored and before its parents are, the file holds a dirty leaf under clean
ancestors. Two things then go wrong. `update_dirty_pages` iterates only subtrees whose roots are dirty, so the page is
skipped. And every later mark of that page returns at the already-dirty leaf and never repairs the ancestors. The
page's node and all its ancestors stay frozen at their old hashes while its contents change. At reload the root still
matches, because the contents had not changed when the process died, so nothing flags the inconsistency. The code
elsewhere is written to be interruption-safe (clean is leaf-first, clear marks pages dirty, a bubble-up pass runs after
a load); mark-dirty is the one path that uses the unsafe order.

### Evidence and test

- Test: `bugs/R7-FPUARCH-1/test.lua`, with `common.lua`, `crash.lua`, `kill-after-leaf-store.py` and the bare-metal
  guest `guest.S`. Run `bugs/run.sh R7-FPUARCH-1`. It needs `gdb` and `ptrace`. It exits 2 with a separate message for
  harness failures.
- The guest keeps writing RAM page 5 through its write-TLB entry. The test stores the machine at mcycle 1000. Under
  gdb it reopens the machine with `SHARING_ALL`, calls `get_root_hash` (which cleans page 5), then calls it again. A
  watchpoint on page 5's leaf byte in the shared `.dpt` fires inside the mark, and the process is killed with SIGKILL
  there. A SIGKILL can land on any instruction, and the shared mapping keeps whatever was stored.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - the dirty-page tree after the crash (leaf to root) is `261:1 130:0 65:0 32:0 16:0 8:0 4:0 2:0 1:0`;
  - the reopened root equals the stored root, so the player's recovery check passes;
  - after running to mcycle 2000, `verify_hash_tree()` fails ("RAM is not marked dirty but is dirty"), and the root
    `0x2893…731f` differs from the uninterrupted run's `0xa17a…1977`.
- Control (`CONTROL=1`, same steps with no kill): the recovered root equals the uninterrupted root and the test
  passes.
- Note from the prover: a normal close leaves the write-TLB pages consistently dirty, so the first update after a
  reopen opens no window. The window opens on a later update in the same process.

### Scenario and reachability

No adversary is needed and every machine state involved is ordinary. The stored PRT player runs its epoch machine with
`SHARING_ALL` and is designed to recover from crashes: `reopen_epoch_directory` and `revert_interrupted_input` reuse
the stored machine when `state.json` records the boundary, and recovery compares only the root. An OOM kill, a restart
or an operator signal inside a hash-tree update leaves the torn file behind. From then on, every state hash,
computation-hash leaf and proof the player builds comes from a stale tree, so it commits a wrong claim or produces
proofs that fail their own verification. Snapshots cloned afterwards (`.revert`, machine-cache entries) copy the
corrupted file forward. The test simulates the crash with `gdb` and SIGKILL, and I did not run the full `prt.lua`
player through it.

### Possible solution

- Make mark-dirty interruption-safe: mark the ancestors before the leaf with a compiler barrier between the stores
  (an interrupted mark then leaves only a dirty ancestor over a clean leaf, which is harmless), and drop the early
  return so each mark walks to the root. That also repairs states left by a power loss.
- As defense in depth, when a shared `.dpt` is reused at load, rebuild its inner nodes from the leaves or cross-check
  them, falling back to marking pages dirty. That also repairs files that `clone_stored` already copied.

### Risks

- Of the issue: a crash in a window of a few instructions, open on every hash-tree update and at load, silently
  corrupts the stored player's machine while its recovery checks pass, and the honest claim is eliminated.
- Of the fix: walking to the root adds O(log pages) byte writes per mark, a small constant factor on hot paths. The
  top-down order needs a compiler fence, or the compiler may reorder the stores.

---

## R8-DYNPLAYERFAULT-1

**The honest bridge's signer wedges for good when its journal holds a candidate that the node does not have, signed
within 15% of the fee or tip ceiling, and that candidate's job is no longer due: no later move or cancel is ever sent,
even after fees return to 1 gwei**

- **Severity:** Critical (`AUDIT.md` section 8: a defect in the honest operator that makes the honest claim miss its
  deadlines and lose). Confirmed by an independent disproving reviewer and reproduced by the orchestrator. Found by
  executing a fault-injection harness (round 8, dynamic testing).
- **Component and area:** `prt-player-bridge`; the transaction journal and fee replacement (`prt-transactions.lua`)
  driven by the bridge tick (`prt-bridge.lua`).
- **Cited rules:** R4 (honest completeness); section 1 completeness; section 2 (honest operator's path); A7 (clocks
  are sized for honest moves that are then never sent).
- **Location:** `doc/recipes/prt-transactions.lua:130-144` (`fees`: replacement floor from the previous candidate),
  `:176-192` (`submit`: rebroadcast only for the same job, otherwise `blocked = "fee ceiling"`), `:85-92`
  (`nonce_record` pins new work to the journal's nonce), `:247-265` (the candidate is stored before it is published);
  `doc/recipes/prt-bridge.lua:684-711,744-748` (`tick` picks the due job or the cancel, both blocked);
  `doc/recipes/prt-cast.lua:93-104,229-231` (a publication HTTP failure raises after the store).
- **Defect:** `submit()` always derives a replacement's fees from the last journaled candidate of the chain nonce:
  priority is at least `ceil(prev.priority * 1.15)` and max fee at least `ceil(prev.max_fee * 1.15)`, and `fees()`
  returns nil above the ceilings (defaults 100 gwei and 10 gwei). On nil, `submit()` rebroadcasts the stored bytes
  only when `previous.job == intent.key`. For any other due job, and for the cancel, it returns
  `{ blocked = "fee ceiling" }`. `nonce_record()` keeps every new job on that same nonce, and only a mined candidate
  releases it. If nobody holds the stuck candidate, nothing can ever mine the nonce, and the floor is computed against
  a transaction that does not exist. Job keys include the event's block hash, so the job changes when its window
  closes, when the opponent moves, or after a reorg.
- **Evidence and test:** `bugs/R8-DYNPLAYERFAULT-1/` (`test.lua`, `mockchain.lua`, `vendor/dkjson.lua`). Run
  `bugs/run.sh R8-DYNPLAYERFAULT-1`. The real bridge tick and transaction journal run on an in-memory EIP-1559 node
  (nonces, blocks, finalized tag, receipts, `eth_getTransactionByHash`, the geth 10% replacement rule). Only the
  bridge's observation is stubbed, to present two jobs. Three fault variants (process killed after the journal store,
  candidate dropped from the node's mempool, and a 9 gwei tip with a drop) end with "job B NEVER mined ... chain
  nonce=0; blocked=fee ceiling" 150 or more healthy blocks later, at a 1 gwei base fee. Two controls (a 20 gwei spike
  with the same drop, and the tip case without a drop) recover, so the harness is sound. The reviewer also made
  `eth_sendRawTransaction` return a JSON-RPC error (`txpool is full`) during the spike, with no crash, and got the same
  wedge. In a randomized run with fee spikes and random RPC faults, reorgs and mempool drops, 30 of 41 seeds (200-240)
  ended wedged. A patched copy that drops the replacement floor when no node holds a candidate of the nonce lets every
  variant mine B (test exits 0).
- **Scenario and reachability:** on the honest operator's path with the default limits, no misconfiguration and no
  guest behavior needed. (1) During a fee spike (base fee about 45 gwei or more, or a suggested tip of about 8.7 gwei
  or more) the honest player signs a candidate for job A at the ceiling. (2) The candidate never reaches the node: the
  process dies between store and publish, `eth_sendRawTransaction` fails (the player exits and is relaunched), or the
  node restarts and loses its mempool. (3) Before A is mined, A's window closes, the adversary moves so that A is
  superseded, or a reorg changes the event's block hash. (4) Fees fall back to 1 gwei. Every tick still reports "fee
  ceiling" for the next due job and for the cancel, the nonce never advances, the honest claim sends no move for the
  rest of the epoch and loses its matches by timeout. The adversary can force step 3 and can help with step 1 or 2 by
  spamming fees or the mempool. The bridge prints "transaction waiting at fee ceiling; observing continues", which
  blames high fees. A human operator could recover by restarting with a higher ceiling or hand-crafting a transaction
  for the nonce; the automated honest operator never does.
- **Possible solution:** in `submit()`, when `fees()` returns nil, check whether every candidate of the nonce is
  unknown to the node and has no receipt. If so, either rebroadcast the stored bytes of the highest-fee candidate that
  is still affordable at the current base fee, regardless of job (this frees the nonce), or sign the new action or the
  cancel from the current fees without the replacement floor. Compute the floor only against candidates that some node
  may still hold, and report "stuck candidate not held by the node" separately from a real fee ceiling.
- **Risks:** an honest operator that survives a benign transient fault at high fees is frozen for the rest of the
  epoch, and a dishonest claim can then win. The fix must keep the exclusive-nonce and journal invariants and must
  never exceed the fee ceilings. "Unknown to the node" is local knowledge: another node or relay may still hold the old
  candidate, in which case only one of the two consumes the nonce and the journal already tracks both. Rebroadcasting
  an obsolete action can revert on chain and waste its fee, which is acceptable.

---

## R10-MANCLI1-1

**Loading a stored machine trusts its page hash-tree cache (`hash_tree.phtc`, outside the hashed state): a valid
template with a poisoned cache reports the right root and passes every documented check, then computes wrong hashes and
proofs**

- **Severity:** Critical (`AUDIT.md` section 8: a rule violation on the honest operator's path that breaks the goal).
  Confirmed by an independent disproving reviewer and reproduced by the orchestrator. **The rating depends on one
  judgment:** the template supplier is trusted (section 4) only for the contents the valid-template conditions cover;
  `THREAT_MODEL.md` section 8 says that once a snapshot meets those conditions, "nothing it carries outside the hashed
  state may affect any transition (R1)", and R1 repeats it for files outside the hashed state. If template distribution
  is treated as entirely trusted, the residue is a Medium (a manual promise that the code does not keep, and a
  `verify_hash_tree` that does not detect it). Found in round 10 (manual and promise checking).
- **Component and area:** emulator; `page_hash_tree_cache` loading of a stored directory, used by the CLI `--load`, the
  JSON-RPC `load` and the PRT player's machine loading.
- **Cited rules:** R1 (no file outside the hashed state may change any transition); R9; R2; R4; section 1
  completeness; section 2 (valid template; the honest operator's path includes obtaining the template and reloading
  it); section 8 (out-of-scope clause for untrusted snapshots, which does not apply to a snapshot that meets the
  conditions).
- **Location:** `src/page-hash-tree-cache.hpp:433-455` (the constructor adopts a stored cache tagged initialized after
  checking metadata only), `:563-575` (`borrow_entry` validates a hit only by the page root), `:352-372`
  (`enqueue_hash_entry` rehashes only the words that differ from the cached page copy and reuses the cached word-level
  siblings); `src/hash-tree.cpp:102-130` (`get_page_proof` takes word-level siblings from the cache entry) and
  `:676-700` with `src/machine.cpp:1708-1711` (`verify_hash_tree` treats a write-TLB-dirty mismatch as consistent);
  `src/cartesi-machine.lua:2884-2889,3132-3135` (`clear_hash_tree` is off by default and the manual never mentions it);
  `doc/recipes/prt.lua:981-986` (the player loads the template with the default runtime and compares only
  `get_root_hash`).
- **Defect:** each cache entry holds a copy of a page and its 256-node word-level tree. On load, the stored cache is
  adopted as is. The only check against the machine is that an entry's page root equals the dense-tree leaf, so an entry
  with the correct page copy and page root but a wrong interior node passes unnoticed. The interior nodes do not feed
  the root reported at load (that comes from the dense and sparse trees), so every load-time check passes. Later, a
  write to a word of that page reuses the poisoned sibling, so the page hash, the dense tree and the root are wrong, and
  `get_proof` for any word of the page returns siblings that do not fold to the root.
- **Evidence and test:** `bugs/R10-MANCLI1-1/` (`test.lua`, `guest.S`, `link.ld`, `build.sh`). Run
  `bugs/run.sh R10-MANCLI1-1`. A bare-metal guest is stored as directory A. Directory B is identical to A except for
  32 bytes of `hash_tree.phtc` (the harness asserts this byte for byte). Results of the run: A and B load with the same
  root, `verify_hash_tree()` is true for both and `cartesi-machine-stored-hash` agrees; but on B `get_proof` of the data
  word does not fold to its root, after one ordinary advance-state input the root is `0xb9f6...` instead of `0x15b2...`,
  and the CLI computes a different mcycle computation hash (`0xb17c...` against `0x58b7...`). Loading B with
  `clear_hash_tree` reproduces A exactly, which rules out any change to hashed state. A harness error exits 2.
- **Scenario and reachability:** the manual presents transferring a stored directory to other hosts and restoring it
  with `--load` as the normal workflow ("the pre-store and post-load state hashes are equal because the same machine
  state is restored"). Whoever controls the channel that delivers the template (developer, release artifact, mirror)
  ships the exact valid contents, whose content hash equals the on-chain commitment, and alters only the cache entries of
  pages that the application touches (its heap or data pages, and the transmit-buffer page that holds the outputs
  root). Every documented check passes: `--initial-hash`, `cartesi-machine-stored-hash`, the player's root comparison and
  `verify_hash_tree`. From the first input that writes a poisoned page, or the first proof of a word in it, the honest
  operator computes wrong mcycle and uarch claims and proofs that the referee's verifiers reject. A dishonest claim with
  the canonical hashes then eliminates the honest claim. No chain data and no adversarial guest behavior are needed.
- **Possible solution:** never trust the persisted cache of a loaded directory without validation. Simplest: on load,
  unless the process is reopening its own directory in place, reset the cache to uninitialized or clear every entry
  (equivalent to `clear_hash_tree` for the cache only; the dense and sparse trees stay usable because their interior
  nodes feed the root that is compared with the commitment). Alternatively recompute each adopted entry's 256-node tree
  from its page copy, check the copy against the live page and `tree[1]` against the dense-tree leaf, and discard failures.
  Defense in depth: on a hit in `borrow_entry`, compare the cached copy with the live page before the incremental
  rehash; make `verify_hash_tree` check the cache interiors; have the player load third-party templates with
  `clear_hash_tree`.
- **Risks:** anyone who controls the template channel can make every honest operator compute wrong claims and proofs
  from the first input on while every documented check passes. Dropping or validating the cache costs time on load (up
  to `phtc_size` pages of 4 KiB plus 255 hashes each) or a slower first root hash on large machines. A partial check
  leaves the same hole, and the fast path where a process reopens its own shared directory after a crash must stay
  correct (see R7-FPUARCH-1, R8-DYNPERSIST-1, R9-GOALRESTORE-1).

---

## R11-FAMCACHE-1

**Loading a stored machine trusts its dense hash-tree files (`<range>.dht`): a valid template with one wrong interior
node keeps the right root and passes `verify_hash_tree`, then gives proofs and hashes that are wrong**

- **Severity:** Critical (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test,
  and reproduced by the orchestrator. Found in round 11 (family expansion). Same family and the same judgment about
  template trust as R10-MANCLI1-1: `THREAT_MODEL.md` section 8 says that once a snapshot meets the valid-template
  conditions, nothing it carries outside the hashed state may affect any transition. If template distribution is
  treated as wholly trusted the residue is Medium.
- **Component and area:** emulator; dense hash-tree files of stored machines (CLI `--load`, JSON-RPC load, PRT
  player).
- **Cited rules:** R1, R9, R2, R4, R10, section 2 valid template, section 8. Reviewer: R1; R9; R2; R4; section 2 valid
  template; section 2 honest operator's path; section 1 completeness; section 8 out-of-scope clause on snapshots (does
  not apply: hashed contents meet the valid-template conditions).
- **Location:** src/memory-address-range.cpp:73-79, src/dense-hash-tree.hpp:61-66, src/hash-tree.cpp:503-535,
  src/hash-tree.cpp:677-735, src/hash-tree.cpp:140-158, doc/recipes/prt.lua:981-994
- **Defect:** memory_address_range adopts <range>.dht and .dpt whenever both filenames are set and mark_pages_dirty is
  off (memory-address-range.cpp:73-79). That is always the case for a directory load, because
  adjust_ar_backing_store_config sets both names. dense_hash_tree maps the file as is and checks nothing. The dense
  tree is a heap array: index 1 is the root, and the page leaves start at 2^(L-1). If one interior node N is changed
  while its parent keeps its correct stored value, the dense root, the sparse tree and get_root_hash are unchanged.
  hash_tree::verify compares only page leaves with their contents and dirty marks, plus the dense root with the sparse
  leaf, and a root mismatch is only printed (it does not set ret=false). So it reports true. Afterwards: (1) get_proof
  returns N as a page-level sibling (hash-tree.cpp:140-158), so proofs of any word under sibling(N) do not fold to the
  root; (2) when a page under sibling(N) is dirtied, update_dense_trees recomputes its ancestors from the stored
  siblings (hash-tree.cpp:503-535), which includes the wrong N, so the range root and the machine root become wrong.
  clear_hash_tree is off by default, and the player only compares get_root_hash.
- **Evidence and test:** `bugs/R11-FAMCACHE-1/` (`test.lua`, `guest.S`, `link.ld`, `build.sh`). Run `bugs/run.sh
  R11-FAMCACHE-1`. It fails while the bug is present. Observed: Failed with the same output on all 4 runs (about 2 s
  each), status 1: "FAIL R11-FAMCACHE-1 (bug present, status 1)". - Template A: 0x0ea838aedcb9...a8c5. - B differs
  from A only in 0000000080000000-100000.dht: 32 bytes, heap node 131. Before it is overwritten, the test asserts that
  node 131 equals get_node_hash(0x80006000,13) and that index 1 is the RAM range root. - Template checks on B all
  pass: cartesi-machine-stored-hash B = 0x0ea838ae...; load root = 0x0ea838ae...; verify_hash_tree = true. - On the
  freshly loaded B, get_proof(0x80005000,5) does not fold (it folds on A and on B with clear_hash_tree). - After one
  advance-state input, the root is 0x15b229ac109472d6... on A and on B with clear_hash_tree, but 0x4cb319e26bb476b1...
  on B. verify_hash_tree on B is still true at that wrong root. - CLI --load --cmio-advance-state
  --mcycle-computation-hash (log2 period 4, one input):   - A = 0x58b779ad6ce14ccb... - B = 0xfeadabeb6d59c321... - B
  --clear-hash-tree = 0x58b779ad... (equals A, so no hashed byte was changed). - Failure line: "FAILURE: a stored
  template that differs from the valid one only in one interior node of its RAM .dht (outside the hashed contents)
  loads with the right root and passes verify_hash_tree, but then: get_proof of the data word on the freshly loaded
  template does not fold to its root; root hash after one input differs from the uninterrupted/clear-cache run;
  verify_hash_tree accepts the wrong root; cartesi-machine --load computes a different mcycle ...
- **Scenario and reachability:** No guest or chain action is needed. The trigger is a stored template whose hashed
  contents and content hash exactly match the valid template and the on-chain commitment, while 32 bytes of its RAM
  .dht (a cache outside the hashed state) are changed. Obtaining and reloading the template is on the honest
  operator's path (section 2). The manual presents shipping and reloading a stored directory as the normal workflow,
  and says load reuses the .dht/.dpt files. Every documented check passes: cartesi-machine-stored-hash, the load root,
  --initial-hash, the player's get_root_hash comparison (prt.lua:981-994) and verify_hash_tree. The wrong node is used
  from the first write under sibling(N) (any ordinary input that touches the application's data or heap pages) or the
  first proof of a word there.
- **Possible solution:** When loading a directory that this process did not write and is not reopening in place, do
  not trust the persisted .dht/.dpt/.sht/.phtc. Either: - force mark_pages_dirty and rebuild every dense tree and the
  sparse tree from the page contents (a full rehash, with every node recomputed from its children), and reset the
  phtc; or - recompute the dense tree bottom-up from the actual pages and reject the load on any mismatch with the
  stored nodes. Make hash_tree::verify check every interior dense node and the sparse nodes against their children,
  and set ret=false on a root mismatch instead of only printing it. Expose a load option or default (for example
  clear_hash_tree, or a verify-on-load option) that the CLI --load, the JSON-RPC load and the PRT player's
  new_machine/new_stored_machine use for third-party templates. A narrower step: have the player always load the
  template it defends with clear_hash_tree and compare the recomputed root with the commitment.
- **Risks:** Risks of the issue: whoever controls the template channel (developer, release artifact, mirror) can make
  every honest operator commit wrong claims and proofs while every documented check passes. That eliminates the honest
  claim, and no adversarial guest or chain action is needed. Risks of the fix: - A full rehash on load costs time
  linear in the machine size, which is bounded but noticeable for multi-GiB ranges. - The fast path that lets a
  process reopen its own shared directory after a crash (R7-FPUARCH-1, R8-DYNPERSIST-1, R9-GOALRESTORE-1) must keep
  working, and stay correct, if it continues to trust the trees. - A partial fix (only the phtc, as R10's fix
  proposes, or only the leaves) leaves this hole open. - Making verify_hash_tree stricter may expose existing benign
  inconsistencies, such as the TLB-dirty case R10 mentions, so those need to be handled explicitly.

---

## R11-FAMFEES-1

**The bridge signs `1.2 x eth_estimateGas at latest` with no worst-case floor, so an honest `joinTournament` or
`winMatchByTimeout` runs out of gas when a front-running Sybil join triggers the pairing branch**

- **Severity:** Critical (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test,
  and reproduced by the orchestrator. Found in round 11 (family expansion). **Fallback-sourced proof:** the
  proof-of-concept prover on Opus 5.5 was stopped by a safeguard and the workflow re-ran it on `sonnet`; the hunter
  and the disproving reviewer (who reproduced it) ran on Opus 5.5. The test exercises the pinned Dave `Tournament`
  contract, which is out of scope, only as the referee the bridge targets.
- **Component and area:** `prt-player-bridge`; `doc/recipes/prt-transactions.lua`.
- **Cited rules:** R4, A7, section 1 completeness, section 2 honest operator's path. Reviewer: Section 1 completeness
  failure (honest operator cannot respond in time); Section 2 honest operator's path / honest claim; A7 (clocks sized
  for a logarithmic number of matches, not one delay per Sybil); R12 (bounded cost of the honest response); Section 7
  (any number of Sybils; race and reorder transactions within chain rules); Section 8 Critical (breaks the goal at a
  reachable state on the honest operator's path).
- **Location:** doc/recipes/prt-transactions.lua:206-215, doc/recipes/prt-transactions.lua:164-169,
  doc/recipes/prt-bridge.lua:523-530, doc/recipes/prt-bridge.lua:684-698, doc/recipes/prt-bridge.lua:335-337,
  doc/recipes/prt-bridge.lua:369-371
- **Defect:** submit() calls eth_estimateGas on the latest block and signs gas = ceil(1.2 * estimate)
  (prt-transactions.lua:206-214), with no lower bound from the action's worst case. The pinned Tournament's
  joinTournament and winMatchByTimeout end in pairCommitment. If the tournament has no dangling commitment, it does
  one SSTORE (it stores the caller as dangling). If one exists, it calls Match.create: three or four zero-to-nonzero
  Match.State slots, a clock start, matchCount, clearing the dangling slot, and a MatchCreated event, about +100k gas.
  Whether a dangling commitment exists is state that any participant changes with a joinTournament, or by winning any
  other match, so the branch at inclusion can differ from the branch at estimation. Measured with the pinned
  Tournament.sol compiled by solc 0.8.30 (viaIR, runs 200) and run in ethereumjs, estimating as the minimal successful
  transaction gas: - joinTournament at height 30: estimate 172,808, bridge limit 207,370, needed after a Sybil join
  274,841, out of gas. - joinTournament at height 62: 195,824, 234,989 and 297,858, out of gas. - winMatchByTimeout:
  136,108, 163,330 and 224,018, out of gas. The honest transaction reverts and its nonce is consumed. The bridge never
  reads receipt.status. receipt() and awaiting_observation() treat the reverted receipt like a successful one and
  suppress the job until the observation head reaches the receipt block (prt-transactions.lua:165-169,
  prt-bridge.lua:686-698). Only then does submit estimate again, against whatever state the adversary has set by that
  time. There is no detection of out-of-gas, no immediate resend with more gas, and no use of the contract's own Gas.*
  allocations (Gas.WIN_MATCH_BY_TIMEOUT = 261,000, for example) as a floor.
- **Evidence and test:** `bugs/R11-FAMFEES-1/` (`test.lua`, `measured-gas.json`, `evm/measure.mjs`, `evm/build.json`,
  `evm/Maker.sol`, `evm/compile.js`, `vendor/dkjson.lua`). Run `bugs/run.sh R11-FAMFEES-1`. It fails while the bug is
  present. Observed: The test fails deterministically: 3 runs with the live EVM measurement and 1 run from the
  recorded fixture, all exit 1. The failing line is: "FAIL R11-FAMFEES-1: prt-transactions.lua signs ceil(1.2 *
  estimate at latest) with no worst-case floor ... joinTournament(h=30): signed 207370 < needed 274841;
  winMatchByTimeout(h=30): signed 163330 < needed 224018; joinTournament(h=62): signed 234989 < needed 297858;
  winMatchByTimeout(h=62): signed 163330 < needed 224018". Per scenario the output also shows that the honest tx, run
  with the signed gas after the Sybil front-run, reverts. The same tx succeeds with the needed gas, so the revert is
  out-of-gas and not a logic revert. After a status-0 receipt at block 17, the unmodified submit() returns waiting
  until tip 21 (3 blocks of waiting, since observation head = tip-4 must reach the receipt block) and then resends.
- **Scenario and reachability:** Reachable with section 7 capabilities only. The adversary posts legal Sybil joins:
  the root accepts any final state, and a child accepts any commitment that ends at the dishonest contested state. It
  front-runs the honest transaction on a public mempool with a higher tip. The pairing branch is normal pinned-Dave
  behaviour. Even an unrelated concurrent join in the same block (another validator) triggers the revert. The bridge
  is the in-scope honest operator (doc/recipes/prt-transactions.lua, prt-bridge.lua), and Dave v3.0.0-alpha.6 is the
  referee it targets (doc/Dockerfile.prt DAVE_REF; the patch changes only geometry). No A1-A7 violation by the referee
  is needed.
- **Possible solution:** Give each contract action a gas floor for its worst-case branch. For every action that can
  reach pairCommitment (joinTournament, winMatchByTimeout, winInnerTournament, winLeafMatch), compute the limit as
  max(1.2*estimate, worst_case[kind]). The worst case can come from a fixed per-action table, measured on the pinned
  build with the dangling-commitment branch plus headroom. It can also come from a second eth_estimateGas with a
  stateOverride that sets a dangling commitment. Also check receipt.status. On a status-0 receipt for a still-due job,
  stop suppressing the job until observation depth. Resend at once with a raised gas limit (for example, double it,
  capped at the block gas limit), and report out-of-gas failures.
- **Risks:** Risks of the issue: an adversary with enough bonds, or ordinary concurrent joins, can delay or prevent
  the honest join or timeout win. The honest claim can then be eliminated, and a dishonest state settles. Benign
  concurrency also causes spurious reverts that waste honest gas and clock time. Risks of the fix: - A larger gas
  limit raises the balance the signer needs (gas * maxFee) and could hit fee-ceiling or balance checks. Unused gas is
  not charged. - A hard-coded table can go stale if the contract version or geometry changes, so it should be tied to
  the pinned artifacts or derived with a state override. - Retrying immediately on status 0 must not fight the
  nonce/replacement logic, and must keep the reorg safety the observation wait currently gives. - The other pairing
  actions (winInnerTournament, winLeafMatch) need the same treatment, or the bug remains there.

---

## R12-SECCACHE2-1

**Loading a stored machine trusts the inner-node hashes of its sparse hash tree (`hash_tree.sht`): a valid template
with one wrong dormant inner node loads with the right root, then yields wrong proofs, roots and claims**

- **Severity:** Critical (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test,
  and reproduced by the orchestrator. Found in round 12 (second-order family expansion). Same family and the same
  judgment about template trust as R10-MANCLI1-1 and R11-FAMCACHE-1: `THREAT_MODEL.md` section 8 says that once a
  snapshot meets the valid-template conditions, nothing it carries outside the hashed state may affect any transition.
  If template distribution is treated as wholly trusted the residue is Medium. **Fallback-sourced discovery:** the
  hunt for this angle on Opus 5.5 was stopped by a safeguard, and the fallback model (`sonnet`) found it; its proof
  and its review ran on Opus 5.5.
- **Component and area:** emulator; sparse hash tree file of stored machines (CLI `--load`, JSON-RPC load, PRT
  player).
- **Cited rules:** R1, R9, R2, R4, R10, section 2 valid template, section 8. Reviewer: R1; R9; R2; R4; R10; section 1
  completeness failure; section 2 valid template; section 2 honest operator's path (obtaining template, storing and
  reloading, computing claims, producing proofs); section 8 snapshot out-of-scope clause does not apply (template
  meets valid-template conditions by content hash).
- **Location:** src/hash-tree.cpp:994-1003 (load validates only left/right/parent/log2_size, never hashes),
  src/hash-tree.cpp:537-601 (update_sparse_tree recomputes only ancestors of changed address ranges from the stored
  hashes of their siblings), src/hash-tree.cpp:70-75 and 203-253 (get_sparse_node_hash_view/get_proof use stored
  sibling hashes), src/hash-tree.cpp:603-605 (get_root_hash returns stored node 1), src/hash-tree.cpp:677-742 (verify
  never inspects inner sparse nodes), src/machine.cpp:307 and 320 (load keeps the file unless clear_hash_tree)
- **Defect:** hash_tree.sht holds an array of sparse nodes (left,right,parent,log2_size,hash; 64 bytes each, hash at
  offset 28). On load the topology fields are compared with the freshly computed ones, but the 32-byte hash of every
  inner node is adopted as is. update_sparse_tree later recomputes a node only when one of its descendant address
  ranges changed, and it recomputes it from the STORED hash of the sibling subtree. Nodes on the path of the
  always-dirty ranges (shadow state, shadow uarch state) and of ranges whose page is in the write TLB are recomputed
  at every update, so poisoning them has no lasting effect (that is why a first attempt showed nothing). A
  sibling-of-path node whose parent is not recomputed at load is dormant: the loaded root, cartesi-machine-stored-hash
  and verify_hash_tree are unchanged. With a 1 MiB RAM machine the topology is: node 73 = H(node 74 [cmio rx and tx
  buffers], node 83 [0x70000000..0x7fffffff, holds the DTB]). Overwriting the 32-byte hash of node 83 (file offset
  83*64+28) with 0x42 bytes changes nothing at load. When the first advance-state delivery writes the rx buffer, node
  73 is recomputed as H(74, poisoned 83) and the root becomes wrong; get_proof of cmio and DTB words uses node 83's
  hash as a level-28 sibling and does not fold to the root. verify_hash_tree has no check on inner nodes, and
  --clear-hash-tree (off by default) restores the right behavior.
- **Evidence and test:** `bugs/R12-SECCACHE2-1/` (`test.lua`, `guest.S`, `link.ld`, `build.sh`). Run `bugs/run.sh
  R12-SECCACHE2-1`. It fails while the bug is present. Observed: I ran the test 3 times on feature/prt-audit. All 3
  runs printed identical output and exited 1 ("FAIL R12-SECCACHE2-1 (bug present, status 1)"). Template A root:
  0x2b026214...9e9a. B differs from A in exactly 32 bytes: the hash of sparse node 83 in hash_tree.sht, at offset
  83*64+28. All the template checks pass on B: - cartesi-machine-stored-hash of B gives 0x2b026214...9e9a. - The
  loaded root equals A's. - verify_hash_tree returns true. What follows on B: - A freshly loaded B gives a get_proof
  of an rx word (0x60000000) that does not fold to the root. A's proof folds. - After one advance-state input, both
  machines reach mcycle 24 with counter 0x1112, so the contents are identical. Root A = 0x533c806c...d61c, root B =
  0x1e784426...e692. - verify_hash_tree on B still returns true with the wrong root. - On B after the input, get_proof
  of a DTB word (0x7ff00000) does not fold. - B loaded with clear_hash_tree reproduces A exactly. - CLI `--load
  --cmio-advance-state --mcycle-computation-hash`: A = 0x485040c55f8f..., B = 0xcea5a8d58cfc..., B with
  --clear-hash-tree = 0x485040c55f8f... (equal to A). The test separates harness errors (exit 2) from the bug (exit
  1). Exit 2 covers these cases: - control A fails its own checks; - the guest misbehaves; - the clear-cache run of B
  disagrees with A; - B differs from A anywhere other than those 32 bytes; - the topology is not what the test expects
  (it requires node 83 to be the right child of node 73 at log2 28 and log2 29, with stored hashes ...
- **Scenario and reachability:** The trigger is a stored template directory whose hashed contents (.bin files) and
  content hash exactly equal the valid template and the on-chain commitment. Only 32 bytes of hash_tree.sht are
  changed, and that file is a cache outside the hashed state. Obtaining and reloading a template is on the honest
  operator's path (section 2). Every documented check passes: cartesi-machine-stored-hash, the loaded get_root_hash
  (which is what prt.lua new_stored_machine compares) and verify_hash_tree. No guest or chain action is needed beyond
  an ordinary first advance-state input, which writes the rx buffer and recomputes the poisoned node's parent. Proofs
  through the poisoned sibling are already wrong on the fresh load. Dormancy requires that no range under the poisoned
  node's parent is recomputed at load (here, no write-TLB entry for the cmio range in the template). That is
  realistic, because an ordinary sfence.vma ensures it, and other dormant sibling nodes exist (flash-drive branches,
  for example).
- **Possible solution:** When loading a stored directory that this process did not write itself and is not reopening
  in place, recompute the hash tree instead of trusting the .sht file: - Rebuild every inner sparse node bottom-up
  from the dense-tree roots and pristine hashes. This costs about as many hashes as there are sparse nodes, which is
  small. - Alternatively, recompute and reject the load on any mismatch with the stored hashes. Also make
  verify_hash_tree check every inner sparse node against H(left, right), and every sparse leaf against its dense root,
  and make it set ret=false on a mismatch instead of only printing it. Apply this together with the R11 (dense
  .dht/.dpt) and R10 (phtc) fixes, for example a full rehash on load or a verify-on-load option. The CLI --load, the
  JSON-RPC load and the PRT player's new_stored_machine should use it for third-party templates. A narrower mitigation
  is for the player to load the template it defends with clear_hash_tree.
- **Risks:** Risks of the issue: whoever controls the template distribution channel (developer, release mirror) can
  make every honest operator commit wrong claims and proofs that do not fold, while every documented check passes.
  That eliminates the honest claim with no adversarial guest or chain action. Risks of the fix: - Recomputing only the
  sparse tree is cheap, but a full rehash covering dense trees costs time linear in the machine size on every load. -
  The fast path that lets a process reopen its own shared directory after a crash must keep working and stay correct.
  - A partial fix, for example only the phtc or only the dense trees, leaves this hole open. - A stricter
  verify_hash_tree may expose benign transient inconsistencies, such as ranges dirtied through the write TLB before an
  update, which must then be handled explicitly.

---

## R12-SECCACHE2-2

**Loading a stored machine trusts its dirty-page trees (`.dpt`): a valid template with one dirty interior node under
clean ancestors loads and verifies cleanly, then every later write under that node is invisible to the hash tree**

- **Severity:** Critical (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test,
  and reproduced by the orchestrator. Found in round 12 (second-order family expansion). Same family and judgment as
  R10-MANCLI1-1 and R11-FAMCACHE-1, and the load-time counterpart of the in-process ordering defects R7-FPUARCH-1 and
  R8-DYNPERSIST-1. **Fallback-sourced discovery:** found by the `sonnet` re-run of a blocked hunt; its proof and its
  review ran on Opus 5.5.
- **Component and area:** emulator; dirty-page tree files of stored machines (CLI `--load`, JSON-RPC load, PRT
  player).
- **Cited rules:** R1, R9, R2, R4, R10, section 2 valid template, section 8. Reviewer: R1; R9; R2; R4; section 1
  completeness; section 2 valid template; section 2 honest operator's path (obtaining and reloading the template);
  section 8 snapshot out-of-scope clause (does not apply: once a snapshot meets the valid-template conditions, nothing
  it carries outside the hashed state may affect any transition).
- **Location:** src/memory-address-range.cpp:62-81 (adopts the stored .dpt, no consistency check),
  src/dirty-page-tree.hpp:82-84 and 109-126 (only byte 0, the init flag, is examined), src/dirty-page-tree.hpp:327-336
  (do_mark_dirty_leaf_position_and_up stops at the first already-dirty node and assumes its ancestors are dirty),
  src/dirty-page-tree.hpp:178-205 (down/up_then_down traverse only through dirty children from the root),
  src/hash-tree.cpp:677-742 (verify compares only leaf and range-root flags, not the interior invariant),
  src/hash-tree.cpp:416-435 (update_dirty_pages iterates dirty_offsets_view from the root)
- **Defect:** The dirty-page tree is a heap array (byte 0 = initialized flag, node 1 = root, page leaves from
  2^(L-1)). Load accepts any file whose byte 0 is non-zero. The code relies on the invariant 'dirty node implies dirty
  ancestors': do_mark_dirty_leaf_position_and_up returns as soon as it meets a node already dirty, and
  dirty_offsets_view/up_then_down only descend from a dirty root through dirty children. If an interior node N is
  stored dirty while the root and the path above N are clean, nothing is detected at load (clean root means no work;
  verify sees every leaf and the range root consistent with the clean contents). Later, any write to a page under N
  (guest store through the write TLB, write_memory, collect paths that call mark_dirty_page_and_up) marks the leaf,
  then stops at N; the root stays clean, so update() never visits the page, dht/sht keep the old page hash and
  get_root_hash returns the stale root. For the 1 MiB RAM range, setting byte 65 of 0000000080000000-100000.dpt to 1
  covers the guest's data page 0x80005000 (leaf 261, parents 130, 65). Evidence disappears quickly: verify_hash_tree()
  is false on the unflushed state ('RAM is not marked dirty but is dirty'), but a following get_root_hash() cleans the
  dpt and verify_hash_tree() then reports true on the stale tree.
- **Evidence and test:** `bugs/R12-SECCACHE2-2/` (`test.lua`, `build.sh`, `guest.S`, `link.ld`). Run `bugs/run.sh
  R12-SECCACHE2-2`. It fails while the bug is present. Observed: I ran it 3 times. All 3 runs printed the same output
  and exited with status 1 ("FAIL R12-SECCACHE2-2 (bug present, status 1)"). - Template A: 0x6d1d6580450a107e... Copy
  B differs from A only in byte 65 of 0000000080000000-100000.dpt (0 changed to 1). - B passes every template check:
  cartesi-machine-stored-hash of B is 0x6d1d6580..., which equals A. B's load root equals A's, and verify_hash_tree
  returns true. - After one advance-state input, the guest counter is 4370 in A, in B and in B loaded with
  clear_hash_tree. - Root after the input: A = 0x27797cbeebc51844..., B = 0xa30164bdb448897e..., B with
  clear_hash_tree = 0x27797cbeebc51844... - B's own post-input state, stored and then rehashed with clear_hash_tree,
  gives 0x27797cbe... B therefore reports a root that is not the content hash of its own contents. - verify_hash_tree
  on B after the input returns true, even though B's root is stale. - get_proof(0x80005000, 12) on B does not fold to
  B's reported root. - CLI mcycle computation hash (log2_mcycle_period 4, one input): A = 0x12609d8e337ba429..., B =
  0xf39d17ce9aacc1ca..., B with --clear-hash-tree = 0x12609d8e... The one-line failure message lists every failed
  check and cites R1, R9, R2 and R4.
- **Scenario and reachability:** Nothing from the guest or the chain is needed. The trigger is a stored template whose
  .bin files and content hash are exactly those of the valid template (the on-chain commitment). Only one byte of a
  RAM <range>.dpt differs, and that file is a cache outside the hashed state. Every documented check passes on it:
  cartesi-machine-stored-hash, the loaded root, verify_hash_tree, and the player's get_root_hash comparison. Obtaining
  and reloading the template is on the honest operator's path. The defect then fires on the first ordinary input whose
  guest writes any page under the poisoned node. No dormancy condition and no TLB precondition apply.
- **Possible solution:** Never adopt a persisted .dpt from a directory the process is not reopening in place. Either:
  - force mark_pages_dirty on load, so every leaf and interior node is dirty and the next update rehashes the whole
  range. Combine this with rebuilding the .dht, .sht and .phtc, as in R10 and R11. - or validate the dpt on load:
  every non-pad leaf must be clean, no interior node may be dirty, and the init byte must hold exactly the dirty
  value. Any other file is rejected or rebuilt. Defense in depth: - make do_mark_dirty_leaf_position_and_up mark up to
  the root, at the cost of more work per write; - have hash_tree::verify check the dpt invariant (a dirty node implies
  a dirty parent); - have the CLI --load, the JSON-RPC load and the PRT player load third-party templates with
  clear_hash_tree and compare the recomputed root with the commitment.
- **Risks:** Risk of the issue: whoever controls the template channel (developer, release artifact, mirror) can change
  one byte of a cache file and make every honest operator compute wrong mcycle and uarch claims, and proofs that do
  not fold. That eliminates the honest claim while every documented check passes. A narrow fix to the .dht values
  (R11's validate-and-compare option) leaves this open. Risks of the fix: - A full rehash on load costs time linear in
  the machine size, which is noticeable for multi-GiB ranges. - Marking up to the root on every write lengthens the
  hot path. - The fast path that reopens the process's own shared directory after a crash must stay correct and keep
  the R7-FPUARCH-1, R8-DYNPERSIST-1 and R9-GOALRESTORE-1 fixes coherent. - A stricter verify_hash_tree may expose
  existing benign inconsistencies, such as the write-TLB dirty case, which must then be handled explicitly.

---

## R1-PLAYER-4

**Epoch listeners fetch, keep and re-sort every InputBox log of every application**

- **Severity:** High (unbounded allocation and time caused by relayed data that the honest operator may decline).
- **Component and area:** PRT player (honest operator); input observation through the epoch listeners and the log
  history.
- **Cited rules:** section 4 (data relayed by the node from others must be bounded); section 7 (any number of
  inputs); R4 and A7 (respond within clocks sized for the operator's own costs); section 8 High.
- **Location:**
  - `doc/recipes/prt-cast.lua:152-160`: `methods:logs` sends only `address`, `fromBlock` and `toBlock`, with no
    topics.
  - `doc/recipes/prt-log-history.lua:70-96`: `get_logs` appends and keeps every log it fetches.
  - `doc/recipes/prt-epoch.lua:20-61`: every poll of an open epoch re-validates, re-sorts and re-indexes every
    retained log.
  - `doc/recipes/prt-epoch.lua:150-158`: each listener starts its own history at the deployment block.
  - `doc/recipes/prt-player.lua:176-220`: one listener per epoch, never removed.

### Problem

The InputBox is shared by every application. The listener downloads every `InputAdded` it has ever emitted, although
it uses only those with `appContract == app` (`prt-epoch.lua:66`) and `appContract` is an indexed topic that could be
filtered. On every poll of an open epoch, it re-sorts the whole history: the comparator parses big integers, about
15k-42k Lua instructions per log per poll. It does this even when no new log arrived. Each epoch keeps its own
full-history copy, and sealed listeners are never dropped. Memory therefore grows with epochs times global InputBox
volume, and poll time with global volume.

### Evidence and test

- Test: `bugs/R1-PLAYER-4/test.lua`. Run `bugs/run.sh R1-PLAYER-4`; it takes about 30 s.
- It drives the real `prt-epoch.lua`, `prt-log-history.lua`, `prt-cast.lua` and `prt-ethereum.lua` decoder, and
  replays `prt-player.lua`'s `open_epochs`/`pass` loop over three sealed epochs and one open epoch. Only the JSON-RPC
  transport is replaced, by an in-memory node whose `eth_getLogs` honors address, block range and topics. dkjson is
  stubbed, since only `json.null` is used.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:

  | Foreign inputs per epoch | Retained by listeners | Steady poll | Foreign logs downloaded |
  |---|---|---|---|
  | 0 | 39.6 KiB | 94k Lua instructions | 0 |
  | 1000 | 6.8 MiB | about 168M (about 1.4 s) | 10000 |
  | 2000 | 13.5 MiB | about 359M (about 3 s) | 20000 |

  Growth is linear in the foreign volume. The application's own deliveries are identical in every run.
- With `R1_PLAYER_4_SIMULATE_FIX=yes`, the transport adds the topic filter `[InputAdded, appContract = app]`, every
  metric returns to the baseline, and the test passes.

### Scenario and reachability

Anyone can call `InputBox.addInput` for any application, cheaply on an L2, and organic use of the shared InputBox
adds to the same pile. Polls slow down and memory grows without bound until passes outrun the response windows, or
the process runs out of memory and crash-loops. The honest claim can then time out. The foreign logs are data the
operator may decline, since it can filter them, so section 8 rates this High rather than Critical. The bridge reads
the shared tournament factory the same way (`prt-bridge.lua:52-72`); that part was not exercised.

### Possible solution

1. Give `chain:logs` a topics argument. Filter the InputBox on `[InputAdded, app]`, the consensus on `EpochSealed`,
   and the factory on its events and indexed fields.
2. Share one incremental history across listeners, or start each listener at the previous seal's block, inclusive.
   Compact sealed listeners.
3. Sort and validate only newly fetched logs, keeping the reorg checks.

### Risks

- Of the issue: an attacker paying only L2 gas, or ordinary InputBox growth, steadily degrades the honest operator
  until it misses deadlines or crash-loops.
- Of the fix: a wrongly encoded topic (32-byte padding, letter case) would filter out the application's own inputs;
  the gap check would catch that, but only as a halt. A later start block must still include an input logged in the
  seal block. Incremental polling must keep the detection of removed logs and changed block hashes.

---

## R1-ROBUST-3

**Each guest automatic yield costs the honest player a host-API round trip, a guest-chosen constant-factor slowdown**

- **Severity:** High (a guest-triggered constant-factor increase in the worst-case cost of a unit of work that stays
  within what the deployment was sized for).
- **Component and area:** PRT player (honest operator); the run loop and the mcycle computation-hash collection,
  which return to Lua at every automatic yield.
- **Cited rules:** R12 (worst-case cost of an mcycle and of a part of a claim); A7 (clocks sized for those costs);
  section 8 High.
- **Location:**
  - `doc/recipes/prt.lua:1369-1379`: the `run_to_stop` loop;
  - `doc/recipes/prt.lua:1481-1500`: `mcycle_computation_hash_run` calls `collect_mcycle_root_hashes` again after
    every automatic yield;
  - `doc/recipes/prt.lua:981-988`: the forked player's machines are JSON-RPC servers;
  - `src/machine.cpp:2415-2445`: each collect call redoes the hash-tree update precondition and serializes the
    partial bundle.

### Problem

Every automatic yield, of any reason, including a zero-length progress report, breaks interpretation and returns to
Lua. The player then makes another host-API call, a JSON-RPC round trip for the forked player: one
`collect_mcycle_root_hashes` on the input's main run, carrying the partial bundle back and forth, or one `run` on a
replay. A guest can yield every few mcycles with a store to `tohost` in a loop, so the per-call fixed cost replaces
interpretation as the dominant cost of an mcycle. It is paid on the main run of the input and on every replay that a
dispute forces.

### Evidence and test

- Test: `bugs/R1-ROBUST-3/test.lua`, with the bare-metal guest `guest.S`, `link.ld` and `build.sh`. Run
  `bugs/run.sh R1-ROBUST-3`.
- Both variants run 12012 guest mcycles; one makes 3000 automatic progress yields of length 0, and the control stores
  to RAM instead. The test drives the real forked player's `input_added` and a replay, and asserts the yield counts
  and that the input is processed.
- Observed by the prover, the reviewer and the orchestrator in every run, forked player:
  - `input_added`: about 112-127 µs extra per mcycle (about 1.44 s against 0.01 s), about 0.5 ms per yield;
  - replay: about 15-19 µs per mcycle;
  - the stored player adds about 13-24 µs per mcycle on `input_added` and almost nothing on replay;
  - locally, resuming with `machine:run` costs about 0.9 µs per yield, against about 45 µs for
    `collect_mcycle_root_hashes`.
- This test measures time. It is not bit-exact, but it fails by a wide margin over its 10 µs-per-mcycle threshold, by
  a factor of about 2 to 12, on a shared 4-CPU host.

### Scenario and reachability

An input that takes over the guest yields automatically in a tight loop. Each forced replay and the main run of the
input slow down accordingly. The reviewer corrected the hunter's magnitude: against the existing guest-reachable
worst case, a guest that dirties a new page every few mcycles costs about 11 µs per mcycle. The yield path is
therefore a constant factor of about 5 to 10, not 10^4. The cost stays bounded and linear, so R12 holds literally,
and a deployment sized per A7 for the true worst case survives. It erodes the margin of the dispute clocks, which is
High. It would be Critical only for a deployment sized below the true worst case, which A7 makes the deployment's
responsibility.

### Possible solution

Amortize automatic yields:

- let `collect_mcycle_root_hashes`, and a replay variant of `run`, continue past automatic yields inside C++ up to the
  chunk end, returning a batch of the yields that matter (tx-output and tx-report data), in order;
- skip per-yield callbacks on replays that do not need outputs;
- drop the redundant precondition work when resuming a chunk.

Size A7 for the measured worst case per mcycle, including dense yields and dirty pages.

### Risks

- Of the issue: one adversarial input slows the epoch and every forced replay by a constant factor, eroding the
  clocks' margin.
- Of the fix: batching must capture the transmit buffer at each yield before the guest overwrites it, and return the
  yields in order, or outputs and their proofs break (A5). The batch must be bounded per call (R8, R12). The hashed
  state must stay identical to an uninterrupted run (R2), including `iflags` X and Y and the fixed-point and target
  results.

---

## R1-TRANSITIONS-1

**Uarch computation-hash builder's fast reset restores only dirtied uarch-RAM words**

- **Severity:** High (a divergence between paths only at demonstrably unreachable states, section 8).
- **Component and area:** emulator; the uarch cycle computation-hash builder `collect_uarch_cycle_root_hashes`, used
  by the PRT player (`collect_uarch_cycle_bundle`, uarch claim builder) and by the CLI's
  `--uarch-cycle-computation-hash`. The affected leaf is the uarch reset at the last uarch position of an mcycle.
- **Cited rules:** R2 (the computation-hash builders must agree with every log verifier and the on-chain verifier at
  the last uarch cycle of an mcycle), R13 (the uarch reset and its pristine state are part of the protocol), R5,
  section 2 (transition form "a uarch step followed by the uarch reset"; valid template with a pristine uarch).
- **Location:**
  - `src/machine.cpp:2887-2914`: the builder's fast reset sets the uarch registers to their defaults and restores
    only the uarch-RAM words in `reset_dirty_words`, which the uarch wrote during the current mcycle. Its only uarch
    precondition (around `src/machine.cpp:2764`) is `uarch_cycle == 0` and `uarch_halt == 0`.
  - The canonical reset writes the whole pristine uarch state: `machine::reset_uarch` (`src/machine.cpp:2133-2149`),
    `do_reset_uarch` in `src/uarch-replay-state-access.hpp:368` (the verifier), and `resetState` in
    `machine-solidity-step` `src/EmulatorCompat.sol`.

### Problem

The builder never checks that uarch RAM is pristine before relying on "restore the words the uarch wrote" to
produce the pristine state. If a uarch-RAM word differs from the pristine image and the uarch does not write it
during the mcycle, the fast reset leaves it unchanged. The reset leaf the builder reports, and the state it leaves
behind, then differ from what `verify_reset_uarch` and `UArchReset.sol` produce. The state transition function is
defined on every state, so this is a path divergence.

### Evidence and test

- Test: `bugs/R1-TRANSITIONS-1/test.lua`. Run `bugs/run.sh R1-TRANSITIONS-1`.
- The test generates, at run time, a uarch RAM image equal to `uarch/uarch-ram.bin` zero-extended to `0x180000`
  bytes, with 8 nonzero bytes at offset `0x170000`. It runs the bare-metal guest `j .` at `0x80000000` on two
  identical machines (equal root hashes checked). One machine closes the mcycle with
  `collect_uarch_cycle_root_hashes`. The other runs the uarch to `UARCH_CYCLE_MAX`, then `log_reset_uarch` and
  `verify_reset_uarch`. A control run with the pristine, zero-extended image agrees on both paths.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - control: reset leaf `38fe2bab…2f90` on both paths;
  - non-pristine uarch RAM: the builder gives `37cf4bfd…3df8`, the verified reset gives `38fe2bab…2f90`.

### Scenario and reachability

If a machine at an mcycle boundary held non-pristine uarch RAM while its uarch registers were in the reset state,
the honest uarch claim would commit, at every reset leaf, a hash that the on-chain verifier does not produce, and
would be eliminated. Today that state is not reachable from a valid template:

- the template's uarch is pristine (section 2), and `prt.lua`'s `assert_rolling_template` checks it;
- the guest cannot write uarch RAM (R8);
- every reset that starts from pristine RAM returns pristine RAM;
- every failure inside the builder leaves `uarch_halt = 1`, or happens after the restore.

Only a custom `uarch.ram` backing store or a deliberate host write produces it, so it is High, not Critical. It
removes the margin that the builder agrees with the verifiers if a future persistence, recovery or cloning change
ever left such a machine on the honest path.

### Possible solution

Keep the optimization but make it fail loudly. Either check, before collecting, that the uarch state node equals the
pristine uarch hash, or check that node after the fast reset, and throw on a mismatch. Alternatively, close each
mcycle with a full `reset_uarch()`.

### Risks

- Of the issue: any change that leaves a machine with reset uarch registers and dirty uarch RAM on the honest path
  turns this into a completeness failure (Critical).
- Of the fix: the check rejects machines with custom uarch RAM images that the CLI accepts today, which are not
  valid templates anyway. A full reset adds a bounded, constant per-mcycle cost (R12) to building uarch claims. The
  rejected-yield path, whose reset leaf is the revert root hash, must stay bit-identical.

---

## R2-ROBUST-1

**Every past epoch's bridge re-observes and retains the full shared log history on every pass**

- **Severity:** High (unbounded allocation and time caused by relayed data that the honest operator may decline;
  growth that erodes the A7 sizing).
- **Component and area:** PRT player and bridge (honest operator); observation by the dispute bridges of settled
  epochs. This is distinct from R1-PLAYER-4, which concerns the epoch listeners' InputBox logs.
- **Cited rules:** R12 and A7 (bounded per-unit cost and sized clocks); R4 and section 1 completeness (the live
  dispute is answered late); section 4 (relayed chain data); section 8 High.
- **Location:**
  - `doc/recipes/prt-player.lua:225-245`: `pass()` ticks every listener ever opened, and none is ever retired.
  - `doc/recipes/prt-epoch.lua:21-23` and `99-119`: a sealed listener keeps returning its bridge, built from the
    consensus deployment block.
  - `doc/recipes/prt-bridge.lua:43-82`: `observe` fetches the factory, the consensus, the root and every child from
    `first_block` with no topic filter, appends every log, and sorts them all.
  - `doc/recipes/prt-bridge.lua:634-642`: `tick()` always calls `refresh()` → `observe()`, even for a done, settled
    bridge (`jobs()` returns nothing when done, line 316).
  - `doc/recipes/prt-log-history.lua:70-96` and `231-255`: each bridge's own history keeps every log forever.

### Problem

Each new block, the player re-observes every historical epoch before it ticks the live dispute, which is ticked
last. Every bridge keeps its own full copy of the shared factory and consensus history and re-sorts it each pass.
Per-pass work therefore grows with the number of epochs times the log volume, quadratically in the application's age
even without an adversary. Memory holds one copy of the shared history per epoch. Foreign `TournamentCreated` logs,
from other instantiations of the shared, permissionless factory, are fetched, copied and sorted by every bridge,
although a bridge needs only its own root's creation log, which is in the seal block it already knows.

### Evidence and test

- Test: `bugs/R2-ROBUST-1/test.lua`. Run `bugs/run.sh R2-ROBUST-1`; it takes about 1.8 s.
- It drives the real `prt-epoch`, `prt-bridge`, `prt-log-history` and `prt-cast` code, replaying
  `prt-player.lua`'s `open_epochs`/`pass` loop over E settled epochs and one live epoch. Only the JSON-RPC node
  (in memory, filtering by address) and the ABI decoder are stubbed. Work is counted in Lua instructions through
  `debug.sethook`, and memory after a full GC.
- Observed, deterministically (instruction counts vary by under 0.1%), by the prover, the reviewer and the
  orchestrator:

  | Setup | Work before the live tick | Retained by bridges |
  |---|---|---|
  | 2 settled epochs | 82k instructions | 270.6 KiB, 84 logs |
  | 8 settled epochs | 534k instructions | 1165.4 KiB, 414 logs |
  | 8 settled epochs, 200 foreign tournaments per epoch | about 17.5M instructions (about 0.2 s) | about 51 MB, 14814 logs |

  A done, settled bridge still issues 9 chain reads per pass.
- With `R2_ROBUST_1_SIMULATE_FIX=yes`, which retires settled bridges with no jobs and keeps only the seal-block
  factory logs, there is no work before the live tick, about 79 KiB is retained, and the test passes.

### Scenario and reachability

This is reached in normal operation as an application ages, for example with hourly epochs, and an adversary can
amplify it cheaply with permissionless tournament clones on an L2. Pass latency and memory then grow without bound
until the live match is answered after its clock expires, or the process runs out of memory. A default restart
reopens every epoch from 0 and hits the same growth; only a manual `--first-epoch` avoids it. The live epoch's own
data stays bounded, and the extra data is data the operator may decline, so section 8 rates this High.

### Possible solution

- Retire a listener once its bridge has observed the next seal and has no remaining jobs, keeping bond recovery and
  result acceptance alive until done.
- Fetch only what is needed: the root's creation log at the seal block, consensus events by topic from the seal block
  on, and root and child logs from their creation.
- Share one consensus and factory history across listeners.
- Tick the live epochs first, or by earliest deadline.
- Default `--first-epoch`, on restart, to the oldest epoch that still has work.

### Risks

- Of the issue: latency and memory grow without bound with age, and an attacker can amplify it, until the honest
  claim misses a clock or the process crash-loops on every restart.
- Of the fix: retiring too early drops pending bond recovery or result acceptance. A reorg that un-settles an epoch
  must reopen its bridge. Topic filters must match the exact event signatures, or the bridge misses its root's
  creation. A shared history must keep each listener's reorg handling correct.

---

## R2-SOLIDITY-1

**Uarch verifiers accept a `WRITE_TLB` ECALL with out-of-range indices, writing a TLB slot image to any leaf where
native throws**

- **Severity:** High (a verifier that accepts a second after-hash only on demonstrably unreachable before-states,
  and a divergence between paths only at such states).
- **Component and area:** emulator, the C++ uarch step verifier (`uarch_replay_state_access::do_write_tlb`); and
  `machine-solidity-step`, the on-chain step (`EmulatorCompat.writeTlbECALL`, `AccessLogs.write4Words`).
- **Cited rules:** R2 (native, producer and verifiers must agree); R3 (every accepted log yields the after-hash the
  transition function defines); R13 and A6 (one transition function across the on-chain and off-chain verifiers);
  section 8 High.
- **Location:**
  - `src/uarch-step.cpp:883-892`: `executeECALL` handles `WRITE_TLB` with `set_index = a0`, `slot_index = a1`.
  - `src/uarch-replay-state-access.hpp:373-378`: `do_write_tlb` has no range check.
  - `src/shadow-tlb.hpp:106-108`: `shadow_tlb_get_abs_addr` wraps modulo 2^64.
  - `src/machine.hpp:746-752`: native `write_unverified_tlb` throws for `set_index > TLB_LAST_` or
    `slot_index >= 256`; native `run_uarch` and `log_step_uarch` use it.
  - `machine-solidity-step` `src/EmulatorCompat.sol` (`writeTlbECALL`): it computes
    `AR_SHADOW_TLB_START + setIndex * TLB_SET_LENGTH + slotIndex * TLB_SLOT_LENGTH` in checked `uint64`, with no
    range check, then calls `AccessLogs.write4Words`.

### Problem

The indices of the `WRITE_TLB` ECALL come from uarch registers. Native interpretation and the log producer reject
out-of-range indices, so such a before-state has no successor. Neither verifier checks them:

- the C++ replay computes the slot address modulo 2^64 and accepts a log that writes the 32-byte slot image
  `[vaddr_page, vp_offset, pma_index, 0]` at that leaf, which can be anywhere, including guest RAM;
- Solidity accepts the same write when the arithmetic does not overflow, and reverts with `Panic(0x11)` when it does,
  where the C++ replay accepts the wrapped address.

One before-state therefore has three outcomes: no successor (native), an arbitrary write (C++ verifier), and an
arbitrary write or a revert (Solidity).

### Evidence and test

- Test: `bugs/R2-SOLIDITY-1/test.lua`. Run `bugs/run.sh R2-SOLIDITY-1`; it takes about 0.2 s.
- It builds, through the Lua API, a before-state with an ECALL at `uarch_pc`, `a7 = 4` and `a1 = 0x3FFFF80`, with
  `a0 = 0` (case A) or `a0 = 2^51` (case B). It hand-builds a 14-access log with genuine proofs whose TLB-slot write
  lands on guest RAM at `0x80000000`.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - native `run_uarch` and `log_step_uarch` throw ("TLB slot/set index out of bounds") in both cases;
  - `cartesi.machine:verify_step_uarch` accepts both logs and returns the forged after-hash.
- Solidity part (not executed on-chain, since no EVM is available): the test checks that `writeTlbECALL` in the pinned
  source has no index check, and models its checked `uint64` arithmetic. Case A yields `0x80000000`, leaf-aligned, and
  `write4Words` hashes the same image as the C++ replay, so Solidity accepts the same write. Case B overflows, giving
  `Panic(0x11)`. The reviewer confirmed this trace by hand.

### Scenario and reachability

Unreachable from any valid template. The only issuer of the ECALL is the pristine uarch program
(`uarch-bridge-state-access.hpp`, `ua_write_tlb_ECALL`). There the set is a constant in {CODE, READ, WRITE}, and the
slot is masked to 0..255 or comes from the flush loop over the set size. The uarch is pristine at every mcycle
boundary, and R8 keeps the guest out of uarch state. Such before-states exist only in dishonest-versus-dishonest uarch
matches, and A1 makes every match against the honest claim start from a canonical hash. The defect removes a margin:
any future break of A1, of the uarch program, or of R8 into uarch state would become an arbitrary-memory-write
primitive that both verifiers accept, and the Lua referee model can predict outcomes the chain does not reach.

### Possible solution

Range-check the indices in the shared `uarch-step.cpp` `executeECALL`, before any multiplication:
`if (set_index > TLB_LAST_ || slot_index >= TLB_SET_SIZE) throwRuntimeError(...)`. Then regenerate `UArchStep.sol`,
so that every implementation agrees the state has no successor. Optionally guard `shadow_tlb_get_abs_addr` against
wrapping.

### Risks

- Of the issue: no direct path to the goal; a loss of defense in depth.
- Of the fix: changing the step verifier changes a pinned artifact, so it needs a coordinated protocol version
  (R13, A6). Honest transitions are unaffected, and gas rises by a few units per `WRITE_TLB` step.

---

## R2-SOLIDITY-2

**On-chain `Memory.validateStrideLength` off-by-one rejects every access to the last leaf**

- **Severity:** High (a divergence between paths only at demonstrably unreachable states).
- **Component and area:** `machine-solidity-step`; `Memory.validateStrideLength`, reached by
  `AccessLogs.readWord`, `writeWord`, `readLeaf`, `writeLeaf` and `write4Words` through `regionFromStride`.
- **Cited rules:** R2 (the on-chain verifier must agree with the log producer and the C++ verifier); R3 (a semantic
  transition must not become a rejection); R10; section 8 High. If the state were reachable, it would be a section 1
  completeness failure.
- **Location:** `machine-solidity-step` `src/Memory.sol:66` (`MAX_STRIDE = MAX_SIZE - 1`) and `src/Memory.sol:98-103`
  (`assert(Stride.unwrap(stride) * s < MAX_STRIDE)`); compared with `src/uarch-replay-state-access.hpp:255-268`,
  which accepts any leaf.

### Problem

For a one-leaf region (`s = 1`), the check requires `stride < 2^59 - 1`, but leaf strides run over `0..2^59 - 1`. The
last leaf, at addresses `0xFFFFFFFFFFFFFFE0`-`0xFFFFFFFFFFFFFFFF` with stride `0x7FFFFFFFFFFFFFF`, fails the assert,
so any read or write of it reverts with `Panic(0x01)` before anything is authenticated. Larger regions are not
affected, because `stride * s <= 2^59 - s` passes for `s >= 2`. The C++ hash tree covers the whole 2^64 space: the
native producer logs such a read, an unmapped word reading as zero with a valid proof, and `verify_step_uarch` accepts
it. The defect only rejects; it never accepts a wrong after-hash.

### Evidence and test

- Test: `bugs/R2-SOLIDITY-2/test.lua`. Run `bugs/run.sh R2-SOLIDITY-2`.
- Not executed on-chain, since no EVM is available. The test reads the constants and the assert directly from the
  pinned `Memory.sol` and evaluates them. It models the Solidity memory path (`truncateToLeaf`, the alignment asserts
  of `strideFromPhysicalAddress`, `Buffer.peekRoot`/`getRoot` with 59 siblings) over the chain encoding that
  `prt-ethereum.lua` `append_log` produces, and replays the native log in `UArchStep.step`'s access order.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - control, `ld x5, 0(x6)` with `x6 = 0xFFFFFFFFFFFFFFD8` (second-to-last leaf): the native log, the C++ verifier and
    the model agree on the after-hash, which validates the encoding, the sibling order and the root computation;
  - `x6 = 0xFFFFFFFFFFFFFFF8`: native `log_step_uarch` produces a 9-access log and `verify_step_uarch` accepts it,
    while the model reverts at the load with `Panic(0x01)`.
- A patched copy with the bound `stride * s <= MAX_SIZE - s` makes the test pass.
- **Executed in round 8.** A round 8 hunter (`DYNSOLEXEC`) compiled the pinned `machine-solidity-step` sources
  unchanged with solc-js 0.8.30 and ran the bytecode in a Rust EVM (`revm`, Cancun). For a uarch `ld` from
  `0xfffffffffffffff8` and from `0xffffffffffffffe0`, the C++ producer logs the step and the C++ verifier accepts it,
  while `UArchStep.step` reverts with `Panic(0x01)` in `Memory.validateStrideLength`. That agrees with the model above.
  The supporting harness is in `bugs/R2-SOLIDITY-2/exec/` (see its `README.md`). The orchestrator could not re-run it:
  its own attempt to install `pyrevm` was refused by the sandbox. The same hunter ran about 100k Solidity checks
  against the C++ verifiers and about 30k mutated proofs, and found no other mismatch.

### Scenario and reachability

Unreachable from any valid template:

- the `address_range` constructor (`src/address-range.hpp:105-117`) requires `start < UINT64_MAX - length` and page
  alignment, so no range covers the last page;
- the pristine uarch reaches guest memory only through PMA lookups and TLB entries filled from page-aligned ranges;
- every other uarch, reset and delivery access is at a fixed low address.

Only a fabricated uarch state touches the last leaf, and A1 keeps it out of matches against the honest claim. If a
future layout ever mapped or touched the top page, an honest leaf proof there would always revert on-chain, which
would be Critical.

### Possible solution

Replace the bound with one that admits every aligned region inside the tree: `stride < (MAX_SIZE >> log2s)`, which
also avoids the multiplication, or `stride * s <= MAX_SIZE - s`. Fix the template if `Memory.sol` is generated, and add
a test that reads and writes the last leaf.

### Risks

- Of the issue: none today; it becomes Critical if the top page is ever touched.
- Of the fix: low. It is more permissive by exactly the last leaf, and proofs are still authenticated at full height,
  so no forged node is admitted. Redeploying the verifier needs a coordinated protocol version (A6, R13).

---

## R4-VARGROWTH-1

**Honest stored player never removes settled epochs' directories or checkpoints, so disk use grows with the
application's age**

- **Severity:** High, as rated by the reviewer. The hunter proposed Critical, by analogy with R1-PLAYER-3. The
  reviewer noted three things:
  - per-epoch disk use is bounded, and growth comes from elapsed epochs, not from guest or relayed data;
  - a guest only turns shared copies into full ones, a constant factor;
  - an operator can prune with the shipped `prt.remove_epoch_directory` and restart with `--first-epoch=N`.

  That removes a margin rather than breaking a rule per unit of work, as with R2-ROBUST-1.
- **Component and area:** PRT player (honest operator); retention of the stored player's per-epoch state.
- **Cited rules:** section 1 (the honest operator runs on the resources the deployment was sized for); R12 and A7
  (sizing margin); R4 (if the disk fills); section 2 (storing and reloading on the honest path); section 8 High.
- **Location:**
  - `doc/recipes/prt-player.lua:150-220`: each epoch gets `state/epoch-N` and `checkpoints/epoch-N+1`, and nothing
    removes either.
  - `doc/recipes/prt.lua:2505-2520` (`store_next_epoch_checkpoint`): a full `machine:store` per epoch.
  - `doc/recipes/prt.lua:1272-1290`: up to 8 stored cache entries are kept after the seal.
  - `doc/recipes/prt.lua:2605-2609`: `remove_epoch_directory`, documented for use "after its epoch's dispute",
    exported at line 2898 and never called by `prt-player.lua`, `prt-epoch.lua` or `prt-bridge.lua`.
  - `doc/recipes/prt-player.lua:177-183`: a restart walks checkpoints from `--first-epoch`, default 0.

### Problem

Every epoch leaves behind its directory and the next epoch's checkpoint. The directory holds a machine clone, up to
8 stored cache entries, inputs, outputs and forests. The checkpoint is a full data write, even on a reflink
filesystem. No operator module ever deletes a settled epoch, and the default restart (`--first-epoch=0`) needs every
checkpoint from epoch 0. Retained disk is therefore about ten machine images per epoch, summed over the application's
life. A guest that rewrites all memory makes every retained clone diverge fully on reflink filesystems; on ext4 they
are full copies anyway.

### Evidence and test

- Test: `bugs/R4-VARGROWTH-1/test.lua`, with a 4 MiB bare-metal guest (`guest.S`, `link.ld`, `build.sh`, built into
  a temporary directory) that accepts each input and writes to every RAM page. Run `bugs/run.sh R4-VARGROWTH-1`; it
  takes about 21 s.
- It replays `prt-player.lua`'s per-epoch honest lifecycle with the real `prt.lua` code, without a chain:
  `load_epoch_checkpoint`, `new_stored_player(state/epoch-N, checkpoints/epoch-N+1)`, two `input_added`, then
  `epoch_sealed`, for 4 epochs. It fails when disk after 4 epochs exceeds twice that after 1 epoch and the operator
  modules contain no removal call. The second condition is a static text search, because the harness cannot settle
  epochs without a chain.
- Observed on ext4, deterministically, by the prover, the reviewer and the orchestrator:
  - retained 240, 449, 658 and 866 MiB after epochs 0-3, about +208 MiB per epoch;
  - a control that removes epoch N-2's directory and keeps only the latest checkpoint stays flat at 376 MiB.

### Scenario and reachability

No adversary is needed. With hourly epochs and the pinned Linux image, each checkpoint alone writes at least the
350 MiB root file system, so an unattended node's disk fills within weeks to months. From then on, `input_added`,
`commit_epoch_state`, `store_uarch_claim` and the seal's checkpoint store fail on every relaunch. The honest claim then
misses its joining window or deadlines (A7), and a dishonest claim can settle. Manual pruning avoids it, but nothing
in the reference operator does it, and `prt-supervise.sh` relaunches with unchanged arguments.

### Possible solution

Retire an epoch automatically once its dispute is finally settled:

- call `prt.remove_epoch_directory(state/epoch-N)`;
- remove `checkpoints/epoch-N`;
- drop its listener and bridge, which also addresses R2-ROBUST-1.

Make a relaunch start from a durably persisted "first unsettled epoch" marker instead of epoch 0. Optionally, clone
the final stored machine at the seal instead of a full `machine:store`, and drop a sealed epoch's cache entries once
its dispute no longer needs them.

### Risks

- Of the issue: an unattended honest node eventually fills its disk and misses deadlines.
- Of the fix: pruning before final settlement (an early terminal flag, a reorg, an open inner tournament) would delete
  what the honest claim needs, so retirement must key on finalized settlement. The marker must be written durably
  before deletion. Directories held open by a live listener's forked servers must be deleted only after it retires.

---

## R4-VARSTATE-1

**After a deep reorg aborts the honest player, the relaunched player silently keeps its stored epoch and claims over
replaced inputs**

- **Severity:** High. It removes the fail-closed margin the design relies on. The trigger, a reorganization of input
  history already confirmed under the operator's policy, is not an adversary capability in section 7, and the chain is
  trusted. That makes it analogous to section 8's "a node that cannot detect a version mismatch" case.
- **Component and area:** PRT player (honest operator); reopening a stored epoch after a relaunch.
- **Cited rules:** R4; R2 (persisting and restoring must leave the state an uninterrupted run would); A3 (inputs come
  from the on-chain record); section 1 completeness failure; section 2 (storing and reloading, computing claims, the
  honest claim).
- **Location:**
  - `doc/recipes/prt.lua:2047-2052`: `input_added` returns for offsets below `input_count` without comparing the
    delivered bytes with the stored `inputs/<n>.bin`.
  - `doc/recipes/prt.lua:2084-2090`: `epoch_sealed` returns when `mcycle_forest` exists, before the "sealed input
    count mismatch" check.
  - `doc/recipes/prt.lua:2723-2787` (`reopen_epoch_directory`): no input identity is recorded or checked.
  - `doc/recipes/prt.lua:2505-2509`: `store_next_epoch_checkpoint` reuses any existing checkpoint.
  - `doc/recipes/prt-epoch.lua:52-60` and `:22`: history changes are detected only against the in-memory
    `self.applied`, which is empty after a relaunch.

### Problem

When confirmed `InputAdded` or `EpochSealed` logs change, the running listener fails closed: "epoch history changed;
restart from a matching checkpoint", or "stable epoch seal was reorganized". This is what `prt-lua-bridge.md`
promises. `prt-supervise.sh` then relaunches the player. The relaunched listener has no memory of the old history,
so it accepts the new branch and redelivers every input. The reopened stored player ignores redelivered inputs below
its count and, for a sealed epoch, returns before checking the input count. It therefore keeps the machine state,
forests, claims and final state it computed from the replaced inputs. Meanwhile the bridge's `inputs`, used for
`winLeafMatch` proofs, hold the new chain bytes.

### Evidence and test

- Test: `bugs/R4-VARSTATE-1/test.lua`, with `vendor/dkjson.lua` (dkjson 2.11, MIT). Run `bugs/run.sh R4-VARSTATE-1`;
  it takes about 4 s.
- It runs the real `prt.new_stored_player` (`reopen_epoch_directory`), the real `prt-epoch.lua` listener and the
  bridge constructor over a mock chain, as `prt-bridge-test.lua` does, with an input policy of 4 blocks and a reorg
  about 7 blocks deep. The template is a bare-metal valid template. A fresh player over the replacement chain gives
  the canonical claim.
- Observed, deterministically, by the prover, the reviewer and the orchestrator, in three scenarios:
  1. Open epoch, input 3's bytes replaced: the running process fails closed (`prt-epoch.lua:59`). The relaunched one
     polls without error and keeps `original-input` while the bridge holds `replacement-input`. Its claim is
     `0x90300a57…c8a2` against the canonical `0x370a1e22…c197`.
  2. Reorg across the seal, input bytes replaced: the running process fails closed (`prt-epoch.lua:22`). The
     relaunched one keeps the old claim.
  3. Reorg across the seal, sealed count changed from 2 to 1: the relaunched player keeps 2 inputs while the chain's
     epoch holds 1, and the claims differ.

### Scenario and reachability

The recipe's demo observes inputs at a numeric depth (`PRT_INPUT_CONFIRMATIONS=8`), and its harness deliberately
creates reorgs deeper than that. Standalone `prt-player.lua` defaults to `finalized`, which needs a finality
reversal. After such a reorg, the relaunched honest player joins with a claim over inputs the chain no longer has and
loses that bond. Its leaf proofs encode chain bytes that disagree with its own claim. The operator believes it is
running, so the correct claim may never enter before the joining window closes.

### Possible solution

- Compare each redelivered input with the stored one (bytes or keccak) in `input_added`.
- Persist the sealed input count and the seal's block in `state.json`, and run the count check before the early
  return in `epoch_sealed`.
- On a mismatch, roll back to the last matching boundary and recompute, or refuse to start with a persistent marker so
  the supervisor does not loop into a silent wrong claim.
- Verify an existing next-epoch checkpoint before reusing it.

### Risks

- Of the issue: after a deep reorg, the honest player silently posts a wrong claim instead of failing closed.
- Of the fix: rebuilding must handle partially written state and must not miss deadlines. Compare input contents and
  order, not block hashes, so benign reorgs within the policy do not cause false aborts.

---

## R11-FAMMASK-1

**The native interpreter returns constant `mvendorid`, `marchid` and `mimpid` while the uarch program and the uarch
and Solidity verifiers read the hashed shadow register**

- **Severity:** High (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test, and
  reproduced by the orchestrator. Found in round 11 (family expansion). A real R2 disagreement between the native
  interpreter and the uarch program, but the differing shadow word is not reachable from a valid template or by any
  input (see below), so the rating is capped at High (section 8: defects only at demonstrably unreachable
  before-states are at most High).
- **Component and area:** emulator; machine-ID CSRs (`interpret.cpp` against `uarch`).
- **Cited rules:** R2, R7, R13, section 8 High. Reviewer: R2; R13; R1; section 2 'State transition function' (defined
  on every state); section 2 'Reachable state'; A1; section 8 High: divergence between paths only at demonstrably
  unreachable states.
- **Location:** src/state-access.hpp:128-138, src/collect-mcycle-hashes-state-access.hpp:135-136,
  src/machine.cpp:973-978, src/i-state-access.hpp:223-228, uarch/uarch-bridge-state-access.hpp:54,94
  (i_prefer_shadow_state reads the shadow word), src/interpret.cpp:1926-1927,2049-2050
- **Defect:** For mvendorid, marchid and mimpid, the native state_access (used by machine::run), the
  collect_mcycle_root_hashes state access and machine::read_reg ignore the hashed shadow word. They return the
  compile-time constants MVENDORID_INIT, MARCHID_INIT and MIMPID_INIT (state-access.hpp:128-138: `return
  MARCHID_INIT;`). uarch_bridge_state_access is an i_prefer_shadow_state, so the uarch program reads these registers
  from shadow memory (DEFINE_SA_READ(marchid) -> prefer_read_shadow_register). verify_step_uarch and UArchStep.sol
  replay that uarch program, so they also use the shadow word. A `csrr rd, marchid` therefore yields different values
  on the two paths whenever the shadow word differs from the constant. The two paths then write different rd values
  and reach different after-hashes from the same before-state.
- **Evidence and test:** `bugs/R11-FAMMASK-1/` (`test.lua`). Run `bugs/run.sh R11-FAMMASK-1`. It fails while the bug
  is present. Observed: Ran 3 times. Exit status was 1 each time and the output was identical. For each of mvendorid,
  marchid and mimpid, starting from one fabricated before-state, a single `csrr a0,<csr>; j .` gives different results
  on the two paths. Example: "FAIL marchid: from the same before-state 4988bf3a30cecb5e, `csrr a0,marchid` gives
  a0=0x16 natively but a0=0x5a4c via the uarch verifiers; mcycle-1 hashes differ (native 834b8e10d1e4a1d6 vs verified
  b27c4b3b0e012392): R2 violated". mvendorid behaves the same way (0x6361727465736920 vs 0x636172746573337a) and so
  does mimpid (0x17 vs 0x5a4d). The summary line is "native interpreter and uarch/verifiers disagree on 3 of 3
  machine-ID CSRs (native returns build constants, uarch reads the hashed shadow word)". Every uarch step passed
  verify_step_uarch, and the closing reset passed verify_reset_uarch. The verifiers therefore accept an mcycle-1 hash
  that differs from the one native interpretation computes. The harness itself works: verify_hash_tree passes on the
  fabricated state, read_word shows the patched shadow word, and both paths end at mcycle 1.
- **Scenario and reachability:** The state is demonstrably unreachable. The guest cannot write these registers:
  0xF11-0xF13 are read-only CSRs (csr_is_read_only, interpret.cpp:2460), and the guest cannot address the shadow range
  (R8). The host write_reg throws 'register is read-only' (machine.cpp:1346-1351). init_processor never writes these
  words. Config processor.registers.marchid=77 is accepted, but the shadow word stays 22 (I checked this with and
  without skip_version_check). A normal load rejects a mismatched word (validate_processor_shadow). The only ways to
  get a differing word are the whole-shadow write_memory special case, or a snapshot load, and both need runtime
  skip_version_check. The manual does not document either one, and the CLI help for skip_version_check says not to use
  it in production. So no valid template can hold such a word, and no input sequence can produce one. A1 keeps a
  fabricated before-state with such a word out of any match against the honest claim.
- **Possible solution:** Make every implementation read the same value. Preferred fix: have the native state_access,
  collect_mcycle_hashes_state_access and machine::read_reg return m_s.shadow.registers.{mvendorid,marchid,mimpid}, so
  that all paths read the hashed word, which is what the uarch and Solidity verifiers already do. The other option is
  to keep the constants and make the uarch bridge return them too. That changes the uarch program, so it needs a new
  pristine hash and new on-chain pins, which is a new protocol version (R13). Also consider making write_memory of the
  whole shadow and snapshot loading refuse non-constant ID words even under skip_version_check, or always re-validate
  them, so that such states cannot be built at all.
- **Risks:** If the native fix is done wrong, it could make native depend on a word that some legacy path leaves
  uninitialized. This is unlikely, because the shadow defaults to the constants. The option that changes the uarch
  side changes the uarch program hash, so it needs redeployment and must not mix versions (A6). Leaving the bug in
  place keeps a latent divergence. It would become Critical if any future documented operation, config path or
  snapshot format let a template carry a non-constant ID word. One example is init_processor starting to honor the
  processor.registers.marchid value from the config, which is currently accepted but ignored. That would make the
  honest native claim disagree with the on-chain uarch verifier on any csrr of these CSRs.

---

## R11-FAMOPERATORIO-1

**The honest stored player writes and fsyncs one durable file per guest output at every input boundary, so its
persistence cost and inode use grow with the number of outputs**

- **Severity:** High (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test, and
  reproduced by the orchestrator. Found in round 11 (family expansion). A guest-chosen constant factor over emulation
  cost, and an inode exhaustion path that makes commit raise and the relaunched player fail again.
- **Component and area:** `prt-player-bridge`; stored player output persistence (`doc/recipes/prt.lua`).
- **Cited rules:** R12, A7, R4, section 8 High. Reviewer: R12; A7; R4 (only under under-provisioning); Section 1
  (resources the deployment was sized for); Section 2 honest operator's path (storing the machine, producing proofs);
  Section 7 (payloads chosen to maximize honest cost); Section 8 High: guest-triggered constant-factor increase within
  sizing.
- **Location:** doc/recipes/prt.lua:2398-2410 (store_outputs), doc/recipes/prt.lua:2457-2468 (commit_epoch_state calls
  store_outputs), doc/recipes/prt.lua:2047-2081 (input_added), src/os-filesystem.cpp:933-940 (write_durable_file:
  mkostemp + write + fsync + rename)
- **Defect:** store_outputs runs `for i, output_data in ipairs(outputs) do fs.write_durable_file(output_data,
  get_output_path(directory, first + i - 1)) end`. For every tx output the guest emitted during the input, this
  creates a temporary file in outputs/, writes it, fflush+fsyncs it and renames it to
  outputs/<epoch_output_offset>.bin. One input boundary therefore costs one fsync, one inode and at least one
  filesystem block (4 KiB) per output. An empty notice payload still uses a full block. All output files of every
  epoch go into the single directory outputs/ and stay for the epoch directory's lifetime, which R4-VARGROWTH-1
  already shows is forever. The per-output cost is not a batched write: there is one fsync per output. The keccaks are
  already logged once per output in outputs.log, so all the data could be persisted in one append plus one sync.
- **Evidence and test:** `bugs/R11-FAMOPERATORIO-1/` (`test.lua`, `build.sh`, `guest.c`, `start.S`, `link.ld`,
  `libc/libc.c`, `libc/string.h`, `libc/strings.h`, `libc/stdio.h`, `libc/errno.h`). Run `bugs/run.sh
  R11-FAMOPERATORIO-1`. It fails while the bug is present. Observed: The test failed (exit 1) in all 3 runs on
  feature/prt-audit, for the reason claimed. Typical output: input 0:     1 outputs ->    16 sync operations (    1
  durable output files), +   30 files in the epoch directory input 1:  2000 outputs ->  2016 sync operations ( 2000
  durable output files), + 2030 files in the epoch directory, 0.60-1.31 s in durable writes of 1.76-2.54 s total
  outputs/ holds 2001 files, du of outputs/: 7.9M (the notices hold about 200 KB of encoded data) low-inode epoch
  directory (inodes used/free 12/500, bytes free 222M) before; after: 512/0, bytes free 86M   first player, input 0
  with 600 outputs: raised: unable to create temporary file '.../epoch-0/outputs/376.bin.tmp.XXXXXX': mkostemp()
  failed: No space left on device   relaunched player, input 0 with 600 outputs: raised: (same error, same output 376)
  FAIL: honest stored player persistence is O(outputs) per input boundary: an input with 2000 outputs costs 2000 more
  sync operations (one write_durable_file+fsync per output under outputs/) and 2000 more files/inodes than one with 1
  (allowed: 4) ... Control: I ran the same test against a scratch copy of prt.lua in which store_outputs appends all
  outputs to one file with a single sync_file. It passed (exit 0): input 1 needed 16 sync operations against 15 for
  input 0, the same number of files, and the low-inode run committed on both attempts. So the test measures the defect
  and passes once it is fixed. The whole test takes about 7 s.
- **Scenario and reachability:** Reachable without breaking any assumption. A correctly designed application, such as
  an echo or airdrop app, emits one notice per payload item, and the input sender picks the item count (section 7).
  The honest bridge (prt.new_stored_player) runs input_added, then commit_epoch_state, then store_outputs at every
  input boundary. It cannot decline the input. No subverted guest and no violation of A1-A7 is needed. Checked: an
  output needs at least about 10k mcycles in a lean guest.
- **Possible solution:** Persist an input's outputs with a constant number of syncs and files per boundary. Append
  each payload to one per-epoch outputs data log, next to outputs.log, and record per-output offsets and lengths (for
  example a 16-byte entry per output, or fold the lengths into outputs.log). Then fsync once and sync the directory
  once per boundary. read_output then reads by offset. On recovery, truncate the data log to the length state.json
  records, as is already done for outputs.log through seek to first*HASH_SIZE. Optionally keep only the hashes on the
  dispute path and stream payloads to a separate, best-effort store, so that a full payload store cannot block
  commit_epoch_state.
- **Risks:** Risks of the issue: - The honest operator's disk and inode use grows about 10-30x faster than its payload
  bytes, and stays for the epoch directory's lifetime. - An under-provisioned host (few inodes, a small volume, a
  directory size limit) makes commit_epoch_state throw at every relaunch. The honest claim then cannot advance or
  answer, which is a completeness failure. - The fsync time is a minor constant: the cost of hashing dirty state
  dominates the worst case. Risks of the fix: - The appended data log needs crash-consistent truncation on recovery,
  so that a torn append is never read as an output. - Offsets and lengths must be validated against state.json. -
  Decoupling payload storage from the commit must not let the outputs Merkle root or outputs.log diverge from the
  payloads served for A5 output proofs. - A format change requires migrating the state.json version.

---

## R13-ROLECOST-2

**The honest bridge re-polls every child tournament ever announced, at least twice per tick, so its per-move latency
grows linearly with the number of Sybil child tournaments**

- **Severity:** High (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test, and
  reproduced by the orchestrator. Found in round 13 (blind adversary personas). The reviewer notes three
  overstatements in the claim: "twice per tick" holds only when the head advanced between observations; observation is
  not one of R12's units of work; and no missed deadline was demonstrated (it needs a very large number of children or
  a slow provider). It survives as a loss of the margin that A7 sizes the clocks for.
- **Component and area:** `prt-player-bridge`; `doc/recipes/prt-bridge.lua` and `prt-log-history.lua`.
- **Cited rules:** R12 (loosely), A7, section 1 completeness, section 8 High. Reviewer: A7; Section 1 completeness
  failure (cannot respond in time), limited to a margin loss; Section 7 (Sybils: any number of claims); Section 8 High
  (removes a margin the goal relies on).
- **Location:** doc/recipes/prt-bridge.lua:43-75 (observe: addresses = factory, consensus, root plus every
  NewInnerTournament child; one history:get_logs per address), prt-bridge.lua:77-80 (sort all logs every observation),
  prt-bridge.lua:303-310 (refresh loops observe), prt-bridge.lua:541-552 (attempt calls refresh again before
  publishing), prt-bridge.lua:641-645 (tick starts with refresh), doc/recipes/prt-log-history.lua:73-100 (get_logs
  issues at least one eth_getLogs per address whenever head advanced)
- **Defect:** Every observation rebuilds the address list from scratch. It adds the child tournament of every
  NewInnerTournament event ever emitted, including finished Sybil-vs-Sybil tournaments the honest claim never enters,
  and calls history:get_logs for each one. get_logs sends at least one sequential eth_getLogs over the single
  persistent HTTP connection for every address whose fetched block is behind the head. A tick observes at least twice:
  refresh at the start, and refresh again inside attempt before publishing. Each observation also re-sorts and
  re-applies every log of the dispute. The latency before each honest response is therefore about 2 x (3 + T) RPC
  round trips plus O(L log L) Lua work, where T is the number of child tournaments and L the number of logs. Both grow
  linearly with the attacker's claim count, not logarithmically. Finished tournaments are never dropped from the
  polling set until the epoch ends.
- **Evidence and test:** `bugs/R13-ROLECOST-2/` (`test.lua`, `vendor/dkjson.lua`). Run `bugs/run.sh R13-ROLECOST-2`.
  It fails while the bug is present. Observed: The test failed the same way on all 4 runs (exit 1). In every run the
  first three lines matched exactly, apart from the CPU timing: K=   10 finished child tournaments: one tick after a
  1-block head advance issued 13 eth_getLogs (17 RPCs total), re-sorted 32 logs, 0.001 s Lua CPU; at 30 ms/RPC = 0.5 s
  K= 1000 finished child tournaments: one tick after a 1-block head advance issued 1003 eth_getLogs (1007 RPCs total),
  re-sorted 3002 logs, 0.080 s Lua CPU; at 30 ms/RPC = 30.2 s K= 1000, 400 RPCs per 12 s block: one publishing tick
  issued 2006 eth_getLogs (2016 RPCs, 60.5 s at 30 ms/RPC, published=true) FAIL: honest bridge per-tick eth_getLogs
  count grows linearly with Sybil child tournaments (13 for K=10, 1003 for K=1000 = 3+K): every finished
  NewInnerTournament child is re-polled on each observation (prt-bridge.lua observe, prt-log-history.lua get_logs)
- **Scenario and reachability:** The trigger is reachable with attacker actions that section 7 allows: post Sybil
  claims, pair them against each other, and bisect each pair to a leaf seal so the root emits NewInnerTournament.
  Every child tournament ever announced goes into the honest bridge's polling set (prt-bridge.lua:53-74). The bridge
  rebuilds that set from scratch on every observation and never prunes it, even for children whose parent match was
  deleted. history:get_logs (prt-log-history.lua:73-97) sends at least one eth_getLogs per address whenever the head
  moved. The honest operator cannot decline this work, because it runs inside its own observe() before any job is
  scheduled. The count of children T is bounded only by the attacker's budget and by chain throughput: each child
  costs a bond plus about 2 x height bisection transactions. An actual missed deadline was not demonstrated. It needs
  a very large T, a slow or rate-limited RPC provider, or tight clocks.
- **Possible solution:** - **Prune the polling set.** Keep a persistent set of tournaments that still matter: the
  root, children on the honest claim's path, and children with outstanding cleanup or bond-recovery jobs. Stop polling
  children whose parent match is deleted and that have no pending job for this bridge. Keep enough to re-add them if a
  reorg makes them current again. - **Batch the queries.** Fetch all tracked addresses in one eth_getLogs call per
  range, since the address field accepts an array. Chunk the array to fit provider limits. Per-tick RPCs then depend
  on new log volume, not on T. - **Apply logs incrementally.** Keep the derived snapshot and apply only the newly
  fetched logs, in order, instead of re-sorting and re-applying every log on each observation. Rewind on a reorg to
  the common ancestor the history already computes. - **Skip the second observation when nothing changed.** In
  attempt(), skip the full re-observation when the head is unchanged. When it changed, apply only the delta.
- **Risks:** Risks of the issue: an attacker with a large budget, or an operator on a slow or rate-limited RPC
  provider, can raise the honest claim's per-move latency and consume its allowance. With tight clocks, it can make
  the bridge miss join windows or response deadlines and get the honest claim eliminated. Provider errors on
  single-block pages are raised, and a relaunch refetches from the deployment block, which makes this worse. Risks of
  the fix: - Pruning children too early can miss events that still matter: bond recovery, eliminateInnerTournament
  cleanup, or a child that a reorg makes current again. prt-lua-bridge.md's TODO already requires keeping earlier
  children until the root settlement is final. - Batched address queries hit provider limits on address count and
  result size, so they still need the halving pager. - Incremental snapshot application adds state that must be
  rewound exactly on a reorg. A mistake there could make the bridge act on stale or duplicated events, which is worse
  than the latency.

---

## R13-ROLEVERSION-3

**The honest player checks only the uarch pristine hash of a deployment, so a verifier build with a different
transition function or dispute-constant split is never detected or refused**

- **Severity:** High (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test, and
  reproduced by the orchestrator. Found in round 13 (blind adversary personas). The reachable impact is the loss of
  detection: a real mismatch needs a deployment that already breaks A6. The CM_MARCHID part of the candidate is weak
  on its own; the core is that the player never compares the verifier code or the split of the dispute constants.
- **Component and area:** `prt-player-bridge`; deployment checks of `doc/recipes/prt-player.lua` and `prt-bridge.lua`
  (`read_geometry`).
- **Cited rules:** R13, A6, section 1 completeness, section 8 High. Reviewer: R13; A6; A2; R4; Section 8 High: node
  that cannot detect a version mismatch while every node runs the deployment's version.
- **Location:** doc/recipes/prt-player.lua:92-99, doc/recipes/prt-bridge.lua:729-749 (read_geometry),
  doc/recipes/prt-deploy.lua:47-52; deployed side: Dave CartesiStateTransition (CM_MARCHID and
  UARCH_PRISTINE_STATE_HASH are its only published constants; LOG2_INPUT_WINDOW_SPAN =
  ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE + ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE), machine-solidity-step
  src/SendCmioResponse.sol:86 (mcycle deadline uses ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE)
- **Defect:** Before joining, the player's only version check against the deployment is `chain:call(state_transition,
  'UARCH_PRISTINE_STATE_HASH()') == cartesi.UARCH_PRISTINE_STATE_HASH`. It does not compare the published CM_MARCHID,
  and does not compare the state-transition contract's code hash with the verifier built from the audited source.
  read_geometry derives log2_mcycles_per_period from levels[1].height minus the local U and then checks only that
  levels[0].height == E+M-p and levels[1].height == p+U. That constrains the sum E+M, not the split. The pristine hash
  covers only the uarch program. It does not cover: - UArchStep.sol (the uarch ISA semantics); - UArchReset.sol (the
  revert-on-reject logic); - SendCmioResponse.sol (delivery preconditions and the mcycle deadline, which depend on
  ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE); - AccessLogs (the hash function); - the position-to-form map in
  CartesiStateTransition (INPUT_MASK and UARCH_CYCLE_MASK). All of these are part of the transition function under
  R13, and none appears in the uarch binary.
- **Evidence and test:** `bugs/R13-ROLEVERSION-3/` (`test.lua`, `run-player.lua`, `vendor/dkjson.lua`). Run
  `bugs/run.sh R13-ROLEVERSION-3`. It fails while the bug is present. Observed: 3 of 3 runs failed the same way, with
  exit 1:   pristine-mismatch  -> refused .../prt-player.lua:93: emulator and Solidity pristine uarch hashes differ
  (control: the harness reaches the player's check)   marchid-mismatch   -> accepted   split-mismatch     -> accepted
  Counter 2^67: player proof encoding = plain uarch step (no input prefix); contract (M=47) form = input-window
  opening (8-byte input prefix, CMIO, step); contract (M=48) form = plain uarch step; player input slot 0, contract
  input slot 1. FAIL: the honest player joins a deployment whose CartesiStateTransition does not implement its
  transition function (CM_MARCHID differs from cartesi.MARCHID; the verifier code is a different build
  (dispute-constant split M=47/E=25)): it checks only UARCH_PRISTINE_STATE_HASH and the sum E+M of the factory
  heights, so it cannot detect and refuse the version mismatch (R13, A6); under the M=47 build its honest proof at
  counter 2^67 reverts. During startup the player made only these calls: the application, consensus and factory views,
  UARCH_PRISTINE_STATE_HASH(), getTemplateHash(), tournamentLevelCount() and tournamentParameters(0/1). It never
  called CM_MARCHID() or eth_getCode.
- **Scenario and reachability:** The check runs on every start of the honest player (doc/recipes/prt-player.lua:92-99,
  before any play). The player joins a deployment by application address and takes the state-transition address from
  the factory. Its only deployment-version checks are UARCH_PRISTINE_STATE_HASH() and bridge.read_geometry
  (prt-bridge.lua:729-749). A grep of the in-scope prt*/game-* modules finds no eth_getCode, CM_MARCHID or code-hash
  comparison. The gap is always present. A wrong outcome (Critical) would also need a deployment that breaks A6, so
  the reachable impact is the section 8 High case: the node cannot detect a mismatch.
- **Possible solution:** At startup, have the player compare the deployed verifier with its own build: 1. Compare
  eth_getCode(state_transition) with the deployedBytecode of CartesiStateTransition in the pinned Dave artifacts (the
  --dave directory). The deploy takes no constructor arguments, so the bytecode is deterministic. Alternatively,
  compare keccak of the code with a hash pinned from a reproducible build of the audited machine-solidity-step and
  Dave revision. 2. Optionally also compare CM_MARCHID and any published dispute constants with the cartesi.* values,
  and refuse to start on any difference. 3. Apply the same code-hash check to the tournament implementation and the
  factory. Their constants (heights and log2step) and the form map also define the protocol. 4. Treat the remaining
  factory geometry as the cross-check it already is.
- **Risks:** Risk of the issue: an operator can join a deployment whose verifier implements a different transition
  function, with no warning. That deployment already breaks A6. There, honest proofs at input-window boundaries or
  with the wrong imcyclemax revert, and the honest claim is eliminated. With A6 holding, only the safety margin is
  lost. Risks of the fix: - An exact bytecode comparison breaks on any recompilation: different compiler settings or
  metadata hash, or a chain-specific deployment such as a proxy or immutables. Honest operators would then refuse
  valid deployments, which is a liveness issue, until the pinned hash is updated through a reproducible build (R13). -
  Pinning the hash in the player couples the emulator recipe to one Dave and machine-solidity-step release. - Adding a
  CM_MARCHID check alone gives false assurance, because CM_MARCHID does not identify the verifier semantics.

---

## R14-INVLOGS-1

**The uarch-cycle hash collector throws when the uarch halts on the step that reaches `UARCH_CYCLE_MAX`, although R4
allows it and the verifiers accept the transition**

- **Severity:** High (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test, and
  reproduced by the orchestrator. Found in round 14 (blind invariant audit by subsystem). A real
  builder-versus-verifier divergence at a boundary that R2 names (the last uarch cycle of an mcycle). The test uses a
  custom uarch image that halts on exactly that step. With the pristine uarch program the trigger would need a
  main-processor instruction that takes exactly 2^20-1 uarch cycles, which the reviewer judged unreachable by bounding
  arguments (plausible worst cases are 10x below), so the rating is capped at High: it is a latent completeness
  hazard, not a reachable failure.
- **Component and area:** emulator; `collect_uarch_cycle_root_hashes` and `collect_uarch_cycle_bundle`
  (`src/machine.cpp`), `uarch_step`.
- **Cited rules:** R4, R2, section 8 High. Reviewer: R2; R4; R5; Completeness failure (section 1); Section 8 High:
  divergence between paths only at demonstrably unreachable states.
- **Location:** src/uarch-step.cpp:1103-1113, src/uarch-interpret.cpp:44-55, src/machine.cpp:2846-2869,
  src/machine.cpp:2984
- **Defect:** Two paths classify the same uarch outcome differently. uarch_step writes the incremented cycle and
  checks `cycle >= UARCH_CYCLE_MAX` before the halt check, so it returns UArchCycleOverflow even when the instruction
  just executed was the halting ECALL (uarch-step.cpp:1105-1113). uarch_interpret forwards that as
  uarch_cycle_overflow (uarch-interpret.cpp:51-52). collect_uarch_cycle_root_hashes then throws 'uarch reached its
  maximum cycle and cannot advance more uarch cycles' (machine.cpp:2866-2868) without checking uarch_halt. R4 says the
  uarch 'halts no later than the uarch step that brings its cycle count to the last uarch position of the mcycle', so
  halting on exactly that step is allowed. The verifier forms define that mcycle completely: the last ordinary step
  verifies, the step at cycle MAX is a no-op, and step plus reset verifies. Only the builder (and
  collect_uarch_cycle_bundle, which calls it at machine.cpp:2984) refuses it. The failed call also leaves the machine
  mid-uarch (cycle=MAX, halt=1), although the code comments say a failed call leaves the machine unchanged.
- **Evidence and test:** `bugs/R14-INVLOGS-1/` (`test.lua`, `halt.S`, `build.sh`). Run `bugs/run.sh R14-INVLOGS-1`. It
  fails while the bug is present. Observed: I ran the test 3 times on feature/prt-audit. It failed the same way each
  time, exit 1, about 20 s per run: "verifiers: step to cycle MAX (halts) verifies, step at MAX is a verified no-op,
  reset verifies" "FAIL: collect_uarch_cycle_bundle cannot build the uarch computation hash of an mcycle the verifiers
  fully accept (uarch halts on the step to cycle MAX): uarch reached its maximum cycle and cannot advance more uarch
  cycles [machine left at uarch_cycle=1048575 uarch_halt=1]" "FAIL R14-INVLOGS-1 (bug present, status 1)"
- **Scenario and reachability:** The mechanism is real, but it is reached only through a deliberate host change: a
  custom uarch RAM image set through the config, which is out of scope for reachability (section 8, section 4). With
  the pristine uarch (uarch/uarch-run.cpp: interpret one mcycle, then halt by ECALL), the defect needs a
  main-processor instruction whose emulation takes exactly 2^20-1 uarch cycles. That would be a knife-edge: one cycle
  more is an outright R4 violation by the uarch program, a different and Critical issue. Uarch registers and uarch RAM
  are not guest-writable (R8), so the "presumed reachable" clause for guest-writable state does not apply. Every
  guest-dependent loop in the interpreter is small and bounded: range-descriptor lookup, page walks of at most 5
  levels, a TLB flush over a fixed 3x256 slots, and rv64i software multiply/divide and soft-float. Boot samples peak
  below 1000 cycles per mcycle, and plausible worst cases stay in the 1e4-1e5 range, at least 10x below 2^20. So the
  triggering state is unreachable, though shown by bounding arguments rather than a formal proof.
- **Possible solution:** In collect_uarch_cycle_root_hashes, when uarch_interpret reports uarch_cycle_overflow, read
  uarch_halt. If it is nonzero, treat the outcome as uarch_halted: break out of the loop and pad with the halted hash,
  then the reset leaf. Throw only when the uarch overflows without halting, which is a genuine R4 violation by the
  uarch program. An alternative is to give the halt check precedence over overflow when the executed instruction is
  the halting ECALL, in uarch_step and uarch_interpret. Because the post-state is identical, that change does not
  alter any verified hash. Still, the Solidity port (generated from uarch-step.cpp) should be regenerated and
  differentially re-tested so the sources stay in lockstep. Also make the collector's failure path leave the machine
  unchanged, or document that it does not, and update the near-limit corpus test to cover a halt at exactly
  UARCH_CYCLE_MAX.
- **Risks:** Risk of the issue: currently none at reachable states. It is a latent completeness hazard. If a future
  uarch or interpreter version had an instruction taking exactly 2^20-1 uarch cycles, the honest operator could not
  build the uarch-level claim or bundles for that mcycle, while the referee accepts every transition. The honest claim
  could then miss its deadline and a dishonest claim win (Critical). The failed call also leaves the machine mid-uarch
  (cycle=MAX, halt=1), so a caller that retries on the same machine gets "microarchitecture is not reset". Risks of
  the fix: the leaf layout at the boundary must stay exactly MAX step-result leaves plus the reset leaf, and the
  halt_position/reset_position assertions in collect_uarch_cycle_bundle must still hold. Other honest-node
  implementations (for example Dave's) and the Lua prt player must adopt the same boundary reading, or nodes would
  compute different uarch-level claims. Changing uarch_step precedence touches generated on-chain code and the pinned
  uarch pristine hash, so A6/R13 would need a new protocol version. The builder-only fix avoids that.

---

## R1-ARCH-1

**CLINT `mtimecmp`-to-cycle conversion wraps, raising spurious timer interrupts (and none for `mtimecmp == 0`)**

- **Severity:** Medium (an undocumented deterministic deviation, consistent across all paths, in behavior that no
  correct guest relies on for isolation or data integrity).
- **Component and area:** emulator; CLINT machine timer interrupts (traps and interrupts).
- **Cited rules:** R7 (traps and interrupts); section 8 Medium; the manual's CLINT description. R2 holds: native and
  uarch agree.
- **Location:** `src/rtc.hpp:46` (`rtc_time_to_cycle` returns `time * RTC_FREQ_DIV` in `uint64` without saturation),
  `src/interpret.cpp:594-600` (`set_rtc_interrupt`), `src/interpret.cpp:2848` (`WFI` wait bound, which matters only in
  unreproducible interactive mode).

### Problem

`set_rtc_interrupt` raises MTIP when `mtimecmp * 8192 <= mcycle && mtimecmp * 8192 != 0`, computed in `uint64`.

- For `mtimecmp` in `[2^51, 2^64)` the product wraps. With `mtimecmp = 2^51 + 1` it is 8192, so a timer interrupt is
  taken at the first RTC tick, although `mtime = mcycle / 8192 < 2^51` can never reach `mtimecmp`.
- With `mtimecmp == 0`, or any multiple of `2^51`, the `!= 0` guard means MTIP is never raised, although
  `mtime >= mtimecmp` always holds (RISC-V privileged spec), and the manual says the CLINT interrupts "whenever mtime
  equals mtimecmp".

The manual documents neither the wrap nor the zero exclusion. The exclusion is probably meant to keep a fresh
machine, whose default `mtimecmp` is 0, from having MTIP pending at boot.

### Evidence and test

- Test: `bugs/R1-ARCH-1/test.lua` with the bare-metal guest `timer.S`, `link.ld` and `build.sh` (compiled at test
  time with `riscv64-unknown-elf-gcc` into a temporary directory). Run `bugs/run.sh R1-ARCH-1`.
- The guest reads a deadline that the host writes at `0x80001000` and stores it to `mtimecmp` with a 64-bit store. It
  then enables MTIE and MIE, busy-loops for about 24000 mcycles and halts with exit 0. Its trap handler records
  `mcause` and `mcycle` and halts with exit 1. Unexpected outcomes are reported as harness errors.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - case A, `mtimecmp = 0x8000000000001`: exit 1, `mcause = 0x8000000000000007` at mcycle 8198;
  - case B, `mtimecmp = 0`: no interrupt is ever taken;
  - a `run_uarch` plus `reset_uarch` replay of mcycles 8190-8200 matches the native root hashes and raises the same
    MTIP, so the deviation is consistent across paths.

### Scenario and reachability

Any M-mode guest code can write `mtimecmp`, and so can an S-mode SBI caller when the firmware forwards the deadline.
The pinned guest stack never writes these values: Linux programs `now + delta` with a bounded delta and stops the
timer with `U64_MAX`, and OpenSBI clears it with `-1`. `U64_MAX` wraps to `2^64 - 8192`, which `mcycle` does not reach
in practice. Only a subverted or bespoke guest can trigger the deviation, and it affects only that guest's own
deterministic computation. The interpreter compiled into the uarch and the on-chain verifier share the logic, so it
cannot split honest from dishonest claims, and the section 1 goal is not threatened.

### Possible solution

Compare in the time domain, which cannot overflow: raise MTIP when `rtc_cycle_to_time(mcycle) >= mtimecmp`. Make
`rtc_time_to_cycle` saturate, which also fixes the WFI bound. For `mtimecmp == 0`, either drop the exclusion and make
the default reset value of `mtimecmp` `UINT64_MAX` (timer disabled), or document the exclusion in the manual.

### Risks

- Of the issue: low. A bespoke correct guest that programs a deadline at or above `2^51`, or that expects an
  immediate interrupt from `mtimecmp = 0`, would see a spurious or a missing timer interrupt.
- Of the fix: any semantic change alters the state transition function. It needs a new protocol version, a rebuilt
  uarch with a new pristine hash, and regenerated verifiers (R13, A6). Dropping the zero exclusion without changing
  the default `mtimecmp` would make MTIP pending in every new machine, changing every template's root hash.

---

## R1-ARCH-2

**Misaligned SC.W/SC.D without a matching reservation fails silently instead of trapping**

- **Severity:** Medium (an undocumented deterministic deviation, consistent across all paths, in behavior that no
  correct guest relies on for isolation or data integrity).
- **Component and area:** emulator; the A extension's store-conditional.
- **Cited rules:** R7 (atomics and traps); section 8 Medium. R2 holds: native and uarch agree.
- **Location:** `src/interpret.cpp:1284-1305` (`execute_SC`).

### Problem

`execute_SC` compares the reservation `ilrsc` with the address before anything else. Only the matching branch calls
`write_virtual_memory`, which holds the alignment check. The other branch sets `rd = 1` and clears the reservation
without any check. A successful LR never leaves a misaligned `ilrsc`, because a misaligned LR traps, so every
misaligned SC takes the silent path. The A extension requires an address-misaligned (or access-fault) exception for a
misaligned LR/SC, and the Sail model checks alignment before matching the reservation. The manual documents no
deviation.

Skipping translation on the no-reservation path, so that an unmapped or unwritable address does not fault, is allowed
by the specification ("a failed SC may be treated like a store"). Only the missing misaligned exception is a defect.

### Evidence and test

- Test: `bugs/R1-ARCH-2/test.lua`, with the bare-metal guest `scmis.S`, `link.ld` and `build.sh`. Run
  `bugs/run.sh R1-ARCH-2`.
- The M-mode guest runs four cases. Its trap handler records `mcause` and `mtval` and skips the trapping instruction.
  The test runs it natively and with `run_uarch`.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - `sc.w` at `0x80002001` and `sc.d` at `0x80002004`, with no reservation: no trap, and `rd = 1` on both paths;
  - controls behave correctly: an aligned `sc.w` without a reservation gives `rd = 1` with no trap, and a misaligned
    `sw` traps with `mcause = 6`;
  - native and uarch end at the same mcycle (65) with equal root hashes.

### Scenario and reachability

Any guest instruction stream reaches it with one misaligned SC. A failed SC performs no memory access, and `rd` is
the constant 1, so nothing leaks and no correct guest depends on the trap. Linux atomics, libcmt and compiler-made
LR/SC loops issue an aligned LR first. Only software that relies on the trap to detect misuse, such as a debugger or
a misaligned-access handler, sees a silent failure. The interpreter compiled into the uarch and the on-chain verifier
share the logic, so the deviation cannot split claims.

### Possible solution

In `execute_SC`, check natural alignment before comparing with `ilrsc`, and raise the store/AMO address-misaligned
exception with `mtval = vaddr` through the same path `write_virtual_memory` uses. Keep the no-reservation fast path
for aligned addresses.

### Risks

- Of the issue: low; buggy guest code sees a silent SC failure instead of a trap.
- Of the fix: it changes the interpreter and so the state transition function. It needs a new protocol version, a
  rebuilt uarch with a new pristine hash, and regenerated verifiers (R13, A6). The trap ordering must follow Sail
  (alignment first, translation only on a reservation match).

---

## R1-ARCH-3

**Page walk ignores PMA failures on PTE accesses**

- **Severity:** Medium (an undocumented deterministic deviation, consistent across all paths, in behavior that no
  correct guest relies on for isolation or data integrity).
- **Component and area:** emulator; Sv39/48/57 page walk (address translation and memory permissions).
- **Cited rules:** R7 (address translation and memory permissions); section 8 Medium. R2 holds: native and uarch
  agree.
- **Location:** `src/translate-virtual-address.hpp`, in `translate_virtual_address`: the A/D update at line 240,
  `write_ram_uint64(a, pte_addr, update_pte); // Can't fail since read succeeded earlier`, and the PTE read failure,
  which returns `false` like a permission failure. Callers such as `fetch_translate_pc_slow` and
  `read/write_virtual_memory` then raise a page fault.

### Problem

The walk reads each PTE with `read_ram_uint64`, which needs a readable memory range, and updates A/D with
`write_ram_uint64`, which also needs a writable one, ignoring its result. Two deviations from the privileged spec
(section 4.3.2) follow:

1. The write can fail, for example when the page table lives in a read-only flash drive or NVRAM. The update is then
   dropped, and the access goes through with A or D still clear. The spec allows only setting A/D or faulting, and
   requires an access fault for the original access type when the PTE store violates a PMA (step 7).
2. When the PTE read fails, because the table pointer is in a device range or an unmapped hole, the guest gets a page
   fault (12/13/15) instead of the access fault (1/5/7) that step 2 requires.

The manual claims Sv39 support and documents neither deviation.

### Evidence and test

- Test: `bugs/R1-ARCH-3/test.lua`, with the bare-metal guest `ptro.S`, `link.ld` and `build.sh`. The read-only page
  table image is generated at run time. Run `bugs/run.sh R1-ARCH-3`.
- An M-mode guest enters S-mode through page tables placed in read-only memory, in the CLINT, or in a hole. It runs
  natively and with `run_uarch`, and a RAM-resident page table is the control.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - fetch, load and store through read-only PTEs with A=0 or D=0 all succeed (the S-mode `ecall` runs, `mcause = 9`)
    instead of raising access faults 1, 5 and 7, and the PTEs keep A/D clear;
  - a root table in the CLINT or in a hole gives `mcause = 12` instead of 1;
  - the control RAM PTE gets A set correctly;
  - native and uarch end at mcycle 222 with equal root hashes.

### Scenario and reachability

Read-only flash drives are a documented configuration, and a subverted guest can point `satp` or a non-leaf PTE
anywhere. But a correct guest such as Linux allocates page tables in RAM; its read-only DAX mappings put only leaf
data pages in flash, never page tables, and it never points `satp` at a device. A missing access fault, or a page
fault instead of an access fault, grants no write to protected memory and leaks nothing. Every path behaves the same,
so claims and verification are unaffected.

### Possible solution

Make the walk report three outcomes: success, page fault and access fault. Map a failed PTE read, and a failed A/D
write (leaving the PTE unchanged), to the access-fault cause of the access type, with `mtval` set to the virtual
address, in every caller: fetch, load, store/AMO, MPRV accesses and TLB fills.

### Risks

- Of the issue: low; only guests that place page tables outside writable RAM observe it.
- Of the fix: it changes the transition function. It needs a new protocol version, a rebuilt uarch, a new pristine
  hash and regenerated verifiers (R13, A6). It touches every translation path, and an error there would cause a
  far worse divergence (R2). The logged access sequence, a PTE read followed by a failed write that must not be
  logged as a write, must stay identical across the record, replay and Solidity verifiers.

---

## R1-ARCH-4

**S-mode `sip` writes can set and clear the read-only STIP and SEIP bits**

- **Severity:** Medium (an undocumented deterministic deviation, consistent across all paths, in behavior that no
  correct guest relies on for isolation or data integrity).
- **Component and area:** emulator; the supervisor interrupt-pending CSR (traps and interrupts).
- **Cited rules:** R7 (traps and interrupts); section 8 Medium. R2 holds: native, uarch and the uarch log verifiers
  agree.
- **Location:** `src/interpret.cpp:2189-2195` (`write_csr_sip`), which writes
  `mip = (mip & ~mideleg) | (val & mideleg)`.

### Problem

`write_csr_sip` uses `mideleg` as its write mask. `WARL_mideleg` limits `mideleg` to SSIP, STIP and SEIP, so once
the firmware delegates the supervisor timer and external interrupts, as OpenSBI does, S-mode can write STIP and
SEIP through `sip`. The privileged spec makes those bits read-only in `sip`, set and cleared only by the execution
environment. Only SSIP is writable. Spike and QEMU restrict `sip` writes to SSIP, and the manual documents no
deviation. `read_csr_sip` and M-mode's `write_csr_mip` are correct.

### Evidence and test

- Test: `bugs/R1-ARCH-4/test.lua`, with the bare-metal guest `sipw.S`, `link.ld` and `build.sh` (built at test
  time). Run `bugs/run.sh R1-ARCH-4`.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - S-mode `csrs sip, STIP|SEIP` sets them (`mip = 0x220`);
  - after M-mode raises STIP and SEIP, S-mode `csrc sip, STIP|SEIP` clears them (`mip = 0`);
  - the control `csrs sip, SSIP` works as specified;
  - a `run_uarch` plus `reset_uarch` replay matches the native root hash at every mcycle, and all 617 uarch steps
    and the reset of the mcycle with the `sip` write were logged and accepted by `verify_step_uarch` and
    `verify_reset_uarch`.

### Scenario and reachability

Any S-mode code reaches it with `csrs`, `csrc` or `csrw` on `sip`. The affected interrupts target S itself.
Undelegated M-level bits fall outside the mask, and U-mode cannot access `sip`, so no privilege boundary is crossed.
Linux's `csrw sip, zero` at entry also clears STIP and SEIP on this emulator, harmlessly, at boot before any template.
Every path agrees, so claims are unaffected.

### Possible solution

Restrict the `sip` write mask to `mideleg & MIP_SSIP_MASK`, adding LCOFIP if Sscofpmf is ever implemented.

### Risks

- Of the issue: low; it affects only S-mode's own delegated interrupts.
- Of the fix: it changes the uarch program, its pristine hash and the state transition function. It needs a new
  protocol version and regenerated verifiers (R13, A6), and templates built with it hash differently.

---

## R2-VERIFIER-2

**Send-cmio-response verifier accepts read accesses carrying unchecked `written`/`written_hash` fields**

- **Severity:** Medium (a verifier that accepts trailing data that does not affect its result).
- **Component and area:** emulator; the off-chain input-delivery log verifier (`verify_send_cmio_response`,
  `replay_send_cmio_state_access`), which the referee model calls at input-delivery positions.
- **Cited rules:** R3 (trailing data is a log validity condition and must be rejected); R11 (one verifier path per
  form; here the verifier families disagree on log validity); section 4 (logs are adversarial); section 8 Medium.
- **Location:** `src/replay-send-cmio-state-access.hpp:123-170` (`check_read`), compared with
  `src/uarch-replay-state-access.hpp:150-166` (`check_access_type`, which rejects these fields).

### Problem

`check_read` validates a read access's type, address, size, read data, read hash and Merkle proof, but never checks
that the access carries no `written` data and no `written_hash`. A relayed delivery log can carry arbitrary bytes in
those fields on any of its read accesses and still verify. The uarch step and reset verifiers reject the same defect
("unexpected written data in 1st access read access ..."). The fields cannot change the after-hash: written values
come from the replay, and reads use only the read data.

### Evidence and test

- Test: `bugs/R2-VERIFIER-2/test.lua`, pure Lua with no guest; it takes about 1 s. Run `bugs/run.sh R2-VERIFIER-2`.
- It takes the honest `log_send_cmio_response` delivery log of a machine waiting at an accepted manual yield. As a
  control, it checks that `verify_step_uarch` rejects junk written data on a read access. It then sets junk
  `written`, `written_hash`, or both on each of the delivery log's three read accesses (`0x308` iflags, `0x330`
  `htif.tohost`, `0x100` mcycle).
- Observed, deterministically, by the prover, the reviewer and the orchestrator: all 9 mutated logs are accepted, and
  each returns the honest after-hash.

### Scenario and reachability

Any claimant can send such a log to the referee model at an input-delivery position: `validate_state_transition_response`
(`doc/recipes/prt.lua:252-273`) and `verify_transition` (`doc/recipes/prt-ethereum.lua:174`) pass it straight to
`verify_send_cmio_response`. The after-hash is unchanged, so the goal is not threatened. The on-chain encoding has no
such fields, so the Solidity verifier is unaffected. Off-chain tooling that treats accepted logs as canonical, for
example by hashing or comparing them, can be confused.

### Possible solution

In `check_read`, reject a read access that carries `written` or `written_hash`, as `check_access_type` does. Better,
share one helper among all replay state-access classes so the verifier families cannot diverge, and review
`check_write` and the receive-buffer region write for similar omissions.

### Risks

- Of the issue: low; the result is unaffected.
- Of the fix: minimal. Honest producers never emit these fields on reads, so only tooling that does starts failing,
  which is intended.

---

## R3-REFEREE-1

**Referee narration raises on adversary-chosen data inside the referee coroutine, killing the referee**

- **Severity:** Medium (violates the manual and stops the referee without affecting the goal: no wrong state
  settles and no uncommitted output is accepted).
- **Component and area:** PRT referee model; the narration (`prtu.story`) that runs inline on the referee's
  coroutines, and the admission of players by the transport.
- **Cited rules:** A5 (the referee must keep accepting validly proven outputs of the settled state); section 4 (data
  relayed from others must not terminate the process); section 5 (the model disagrees with the normative manual);
  section 7 (Sybils); section 8 Medium.
- **Location:**
  - `doc/recipes/prt.lua:758-790`: `wait_for_outputs` calls `story.report_output` at line 786, after accepting an
    output, outside any `pcall`.
  - `doc/recipes/prtu.lua:260-263`: `report_output` decodes every output as `Notice(bytes)`.
  - `doc/recipes/prtu.lua:76-91`: `report_claims` concatenates the posters' labels, called from `prt.lua:748` and
    `prt.lua:494`.
  - `doc/recipes/game-transport.lua:530-541`: `announce` stores `message.label` of any JSON type.
  - `doc/recipes/game-transport.lua:121-140`: `dispatcher.step` rethrows every coroutine error as fatal.

### Problem

Narration code runs inline on the referee's fatal path, and it assumes well-formed data:

- **Voucher outputs.** `validate_output_response` correctly treats output payloads as opaque. But after accepting
  one, `report_output` decodes it as a `Notice` and raises "function selector mismatch" for a `Voucher`, a
  `DelegateCallVoucher`, or any other output. The referee process exits, and no other output of the settled state can
  ever be accepted. The manual says the referee "waits for output proofs indefinitely" (around
  `doc/README.md:11150-11158`).
- **Player labels.** A player that announces a non-string label, for example `true`, makes `report_claims` raise in
  `table.concat` when the claims are narrated, before any match, so the epoch never settles. `prt.lua:157` says labels
  "never influence protocol state or ordering".

### Evidence and test

- Test: `bugs/R3-REFEREE-1/test.lua`, with `scenario.lua` (adapted from the R1-REFEREE-2 harness). Run
  `bugs/run.sh R3-REFEREE-1`; it takes about 0.4 s.
- It runs the real referee end to end (`prt.new_referee`, `run_referee`, `open_mcycle_tournament`,
  `wait_for_outputs`) over `game-test-server` and the real `prtu.protocol` JSON. The settled state is synthetic but
  well formed: an accepted manual yield, with the transmit buffer holding the root of a full-height tree of two
  outputs. The narration hooks are only wrapped to print markers.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - `voucher`: the referee accepts the valid proof of output 0, a `Voucher(address,uint256,bytes)` with selector
    `0x237a816f` (the encoding libcmt emits), then dies with "evmu.lua:39: function selector mismatch". Output 1 can
    never be accepted.
  - `label_true`: a Sybil announcing `{"role":"player","label":true}` with a valid claim kills the referee in
    `prtu.lua:89` before any match.
  - controls (`notice`, two notice outputs; `label_string`, a string label): the honest claim wins and both outputs
    are accepted.

### Scenario and reachability

Vouchers are standard outputs of correctly designed applications. Once the winner settles, a voucher's proof is
public, `prove_output` goes to `EVERYONE`, and the honest player itself offers its last output (`prt.lua:1899-1900`).
So any party can stop output acceptance after the first non-Notice output. The label case needs only the section 7
power to post claims as a Sybil. Neither case affects claim computation, proofs, or which state settles.

### Possible solution

Make narration total on adversary data:

- in `report_output`, `pcall` the decode, and narrate the selector and raw bytes, or the decoded voucher fields, on
  failure;
- in `report_claims`, apply `tostring` to labels;
- in `announce`, accept only bounded string labels, defaulting to the role.

As defense in depth, wrap every `story.*` call in a `pcall` that logs and continues.

### Risks

- Of the issue: on demand, any party halts output acceptance, and a single Sybil prevents an epoch from settling; the
  same applies to any production code that reuses this narration inline.
- Of the fix: a `pcall` applied beyond the `story.*` calls could hide real referee bugs. Rejecting non-string labels
  may break harnesses that rely on missing labels, which should keep defaulting to the role.

---

## R4-VARSPEC-1

**Page walk accepts non-leaf PTEs with the reserved A, D or U bits set instead of raising a page fault**

- **Severity:** Medium (an undocumented deterministic deviation, consistent across all paths, in behavior that no
  correct guest relies on for isolation or data integrity).
- **Component and area:** emulator; the Sv39/48/57 page walk.
- **Cited rules:** R7 (address translation); section 8 Medium. R2 holds: native and uarch agree.
- **Location:** `src/translate-virtual-address.hpp:181-187` rejects reserved bits 60-54, PBMT and N for every PTE;
  the non-leaf branch (`xwr == 0`, around line 259, `pte_addr = ppn;`) follows the pointer without checking A
  (bit 6), D (bit 7) and U (bit 4).

### Problem

Since privileged spec 1.12, A, D and U are reserved in non-leaf PTEs, and step 3 of the translation algorithm
requires a page fault for the original access type when a reserved bit is set. Spike and QEMU implement that check.
The emulator already applies the 1.12 reserved-bit rules to bits 63-54, and implements the 1.12 `menvcfg`/`senvcfg`
CSRs, but translates through a non-leaf PTE with A, D or U set. The manual documents no deviation.

### Evidence and test

- Test: `bugs/R4-VARSPEC-1/test.lua`, with the bare-metal guest `pte.S`, `link.ld` and `build.sh`. Run
  `bugs/run.sh R4-VARSPEC-1`.
- The guest builds a correct Sv39 identity map and sets A, D or U in the root (non-leaf) PTE. It then fetches in
  S-mode, and loads and stores in M-mode with MPRV and MPP=S.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - all 9 cases complete (mcause 9, 11, 11) where page faults 12, 13 and 15 are required;
  - controls without the extra bit behave as expected;
  - setting bit 54, which the emulator already rejects, faults correctly, so the harness detects faults;
  - a uarch replay of the fetch case matches native at every mcycle.

### Scenario and reachability

Any guest that builds page tables can reach it. The spec requires software to clear these bits, and Linux and
OpenSBI do, so no correct guest relies on the fault. All paths agree, so claims are unaffected.

### Possible solution

In the non-leaf branch, before following the pointer, return a page fault when
`pte & (PTE_A_MASK | PTE_D_MASK | PTE_U_MASK)` is nonzero. Alternatively, document which privileged spec version the
walk follows.

### Risks

- Of the issue: low.
- Of the fix: it changes the state transition function. It needs a new uarch, pristine hash and verifiers, as a
  coordinated protocol version (R13, A6). Software that wrongly leaves these bits set would start faulting; the
  shipped stack does not.

---

## R4-VARSPEC-2

**Each interrupt taken decrements `instret`/`minstret`**

- **Severity:** Medium (an undocumented deterministic deviation, consistent across all paths, contradicting the
  manual, in a performance counter that no correct guest relies on for isolation or data integrity).
- **Component and area:** emulator; the retired-instruction counter and trap entry.
- **Cited rules:** R7; the manual's definition of `icycleinstret` (`doc/README.md:7312`: "the difference between
  `mcycle` and the architectural instruction count"); section 8 Medium. R2 holds.
- **Location:** `src/interpret.cpp:451-453`: `raise_exception` increments `icycleinstret` for every cause, interrupts
  included. `src/interpret.cpp:5736-5746`: interrupts are raised in the outer loop without advancing `mcycle`.
  `src/interpret.cpp:1759-1766` and `1914-1919`: `instret = mcycle - icycleinstret`.

### Problem

For a synchronous exception, the increment cancels the mcycle the faulting instruction consumed without retiring. An
interrupt, however, is taken before the next fetch and consumes no mcycle. The increment then lowers `instret` by one,
although nothing failed to retire. Zicntr defines `instret` as instructions retired.

### Evidence and test

- Test: `bugs/R4-VARSPEC-2/test.lua`, with the bare-metal guest `instret.S`, `link.ld` and `build.sh`. Run
  `bugs/run.sh R4-VARSPEC-2`.
- The guest measures `minstret` across the same three retired instructions, with and without a machine software
  interrupt raised by a store to the CLINT `msip`.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - without the interrupt: `dinstret = 3`, `dmcycle = 3`;
  - with it: `dinstret = 2`, `dmcycle = 3`, `mcause = 0x8000000000000003`;
  - uarch matches native in both cases.

### Scenario and reachability

Any guest that takes interrupts and reads `instret` sees it drift. Linux takes timer interrupts constantly, so user
`rdinstret` and perf measurements drift. All paths agree, so claims are unaffected.

### Possible solution

Increment `icycleinstret` only for synchronous exceptions: skip it when `cause & MCAUSE_INTERRUPT_FLAG` is set.
Alternatively, document the behavior and redefine `icycleinstret` in the manual.

### Risks

- Of the issue: only guest `instret` measurements are affected.
- Of the fix: it changes the state transition function and needs a coordinated protocol version (R13, A6). Native,
  uarch and Solidity diverging on every interrupt would be Critical (R2).

---

## R7-FPMEM-1

**A PLIC claim/complete write clears the M-mode software-written `mip.SEIP` bit, because the PLIC signal and the
software bit share one stored bit**

- **Severity:** Medium (an undocumented deterministic deviation, consistent across all paths, in behavior that no
  correct guest relies on for isolation or data integrity).
- **Component and area:** emulator; the PLIC model and the supervisor external interrupt (traps and interrupts).
- **Cited rules:** R7 (traps and interrupts); section 8 Medium. R2 holds: native, uarch and the step and reset log
  verifiers agree.
- **Location:** `src/plic-address-range.cpp:83-103` (`plic_write_claim_complete` runs
  `reset_mip(MIP_MEIP_MASK | MIP_SEIP_MASK)` when no PLIC source is pending), `:57-62` and `:198-219`;
  `src/interpret.cpp:2406-2410` (`write_csr_mip` writes M-mode's SEIP into the same stored bit).

### Problem

By the privileged spec, `mip.SEIP` is writable by M-mode, and the value seen by CSR reads and by the interrupt logic
is the logical OR of that software bit and the external interrupt controller's signal. The emulator stores one bit
and lets both the CSR write and the PLIC model drive it. In a reproducible machine no PLIC source is ever pending, so
any store of a value from 1 to 31 to the claim/complete register (`0x40300004`) takes the "nothing pending" branch and
clears SEIP. That destroys a supervisor external interrupt that M-mode injected in software, and S-mode can trigger it
although it has no architectural way to clear that bit. The PLIC specification also says completing an id that was
never claimed should be ignored; it is not. The manual does not document either behavior.

### Evidence and test

- Test: `bugs/R7-FPMEM-1/test.lua`, with the bare-metal guest `seip.S`, `link.ld` and `build.sh`. Run
  `bugs/run.sh R7-FPMEM-1`; it takes about 15 s.
- Observed, deterministically, by the prover, the reviewer and the orchestrator:
  - control, with no store to the register: the injected supervisor external interrupt is taken
    (`scause = 0x8000000000000009`);
  - M-mode case: `mip` goes from `0x200` to `0x0` after the claim/complete write;
  - S-mode case: after S-mode stores `1` to the register and sets `sstatus.SIE`, no supervisor external interrupt is
    taken;
  - a uarch replay agrees with native at all 54 mcycles, with 6,324 uarch steps logged and verified.

### Scenario and reachability

Any guest reaches it with one 32-bit store, after M-mode sets `mip.SEIP`. The only actor that loses anything is S-mode,
which loses an interrupt aimed at itself. A correct kernel does not complete an unclaimed id, and M-mode never relies
on S-mode taking a software-injected interrupt. All paths agree, so claims are unaffected.

### Possible solution

Separate the two sources: let the PLIC drive only its own signal, compute the effective SEIP as the OR of the software
bit and that signal, and make `csrrs`/`csrrc` read-modify-write use only the software bit. As a smaller step, ignore a
complete write whose id was not claimed.

### Risks

- Of the issue: low; hashes, proofs and the honest operator are unaffected.
- Of the fix: it changes the interpreter and possibly the state layout, so it needs a coordinated protocol version, a
  rebuilt uarch and a new pristine hash (R13, A6). It also changes what `csrr mip` and `sip` return on existing
  unreproducible machines.

---

## R8-DYNPERSIST-1

**`write_memory`, `write_word` and `fill_memory` store the data into shared RAM before marking the page dirty, so a
process stop in between leaves a stored machine whose hash tree does not commit to its contents**

- **Severity:** Medium (`AUDIT.md` section 8: a persistence defect off the honest operator's path; R9). Confirmed by an
  independent disproving reviewer and reproduced by the orchestrator. Found by executing a crash-injection harness
  (round 8, dynamic testing). **Found only by the fallback-model hunter** (`sonnet`): the Opus 5.5 hunt for this angle
  was stopped by a safeguard, so this confirmation is fallback-sourced. The prover and the reviewer ran on the primary
  model.
- **Component and area:** emulator; persistence ordering of shared backing stores (R9). A different root cause from
  R7-FPUARCH-1, which is about the order inside the dirty-page tree.
- **Cited rules:** R9 (a persisted hash equals the root of the actual contents, including after interrupted updates);
  R2 (persist and restore agree with an uninterrupted run); section 8 Medium.
- **Location:** `src/machine.cpp:1862-1869` (`write_memory`: copy, then `mark_dirty_page_and_up`), `:1890-1899`
  (`fill_memory`: same order), `:2063-2065` (`write_word`: same order). Reached also through
  `state_access::do_write_memory` (`send_cmio_response`, `src/state-access.hpp:459`) and
  `uarch_state_access::do_write_word` (uarch ECALL writes, `src/uarch-state-access.hpp:94`).
- **Defect:** with `SHARING_ALL` the RAM `.bin`, `.dpt` and `.dht` files are `MAP_SHARED`, and a load trusts the
  `.dpt` and `.dht` (`src/memory-address-range.cpp:76-79`). The three writers store the data first and mark the page
  dirty afterward, and nothing else records the pending change (host API writes bypass the write TLB that protects
  interpreter writes). A stop between the two leaves the new bytes in RAM, the page clean in the `.dpt` and the old
  page hash in the `.dht`. The reloaded root is the exact pre-write root, so a check of the form "root equals the
  expected boundary root" passes on different contents.
- **Evidence and test:** `bugs/R8-DYNPERSIST-1/` (`test.lua`, `common.lua`, `crash.lua`,
  `kill-after-data-store.py`). Run `bugs/run.sh R8-DYNPERSIST-1`. Under gdb, a hardware watchpoint on the shared RAM
  mapping kills the process the instant the written byte changes, for `write_memory` and for `write_word`. After the
  reload, the word is `0xabab...` but `get_root_hash` equals the pre-write root, the oracle root of an uninterrupted
  machine given the same write differs, and `verify_hash_tree()` fails with "page ... is not marked dirty but is
  dirty". The control (no kill) matches the oracle. The harness checks that the watchpoint fired and the kill landed,
  otherwise it exits 2. `fill_memory` has the same shape but no Lua binding, so it is not exercised.
- **Scenario and reachability:** any crash, kill or OOM in that window of a process that holds a machine loaded with
  shared backing stores, reached from the public C or Lua API, from `send_cmio_response`, or from uarch ECALL writes
  (the CLI with `--load=...,sharing:all` is one such user). The stored PRT player is protected: it writes to its shared
  epoch machine only after cloning `machine.revert`, which `revert_interrupted_input` (`doc/recipes/prt.lua:2636`)
  restores when its root matches `state.json`, and its replay and proof machines are temporary clones deleted on
  reopen. No honest-operator path that reloads such a store after an interrupted API write without a snapshot was
  found, hence Medium; it would be Critical if a player change wrote to a shared machine outside a snapshot window.
- **Possible solution:** mark the page dirty before storing the data in `write_memory`, `fill_memory` and
  `write_word` (keep the `memcmp` check first so unchanged pages stay clean), and make the marking itself crash-safe
  in the order R7-FPUARCH-1 requires. A sturdier alternative is an "open" flag in the shared directory, set on load
  and cleared on clean shutdown, that forces `mark_pages_dirty` and a rebuild after an unclean stop.
- **Risks:** a tool that relies on reloading a shared store after a crash gets a root hash that does not commit to the
  contents, and a later run on it yields roots that differ from an uninterrupted run. Marking first can only produce
  spurious dirty pages, which cost a rehash and are hash-neutral, provided all validation stays ahead of the mark. None
  of these gives power-loss consistency without `msync` or `fsync` barriers.

---

## R9-GOALRESTORE-1

**Mcycle hash collection defers the dirty marks of page-walk A/D writes to the end of each sampling period, so a
process stop during `collect_mcycle_root_hashes` leaves a shared stored machine whose hash tree does not commit to its
contents**

- **Severity:** Medium (`AUDIT.md` section 8: a persistence defect off the honest operator's path; R9). Confirmed by an
  independent disproving reviewer and reproduced by the orchestrator. Found in round 9 (attack-goal driven).
- **Component and area:** emulator; the mcycle collection accessor and the dirty-page tree. A different root cause from
  R7-FPUARCH-1 (order inside the dirty-page tree) and R8-DYNPERSIST-1 (host API writers): this one is the deferred mark
  of a guest-driven write.
- **Cited rules:** R9 (a persisted hash equals the root of the actual contents, including after interrupted updates);
  R2 (persist and restore agree with an uninterrupted run); section 8 Medium. `i-accept-dirty-pages.hpp:29-40` states
  that every other context marks each page at the moment of the write.
- **Location:** `src/collect-mcycle-hashes-state-access.hpp:51-53,77-83,459-463` (the class is not an
  `i_accept_dirty_pages`; `do_write_memory_word` only inserts the page into the in-process `context.dirty_pages`),
  `src/translate-virtual-address.hpp:61-77` (`write_ram_uint64` writes the PTE and marks the page only for
  `i_accept_dirty_pages` accessors), `src/machine.cpp:2484-2504` (the set reaches the shared `.dpt` only after
  `interpret_with_console` returns at the period target).
- **Defect:** while collecting hashes, a page-walk write of an accessed or dirty bit changes the PTE in the
  `MAP_SHARED` RAM file, and the only record of the change is an in-process set that is flushed at the end of the
  period. Ordinary stores are safe because their page sits in a write-TLB slot, which persists in the shadow TLB file
  and is re-marked on load. A walk installs only a read or code TLB entry for the target page, so nothing persistent
  records the changed page-table page. After a stop, the `.dpt` leaf is clean and the `.dht` hash is old; the A bit is
  already set, so re-running never writes that PTE again and the page is never re-hashed.
- **Evidence and test:** `bugs/R9-GOALRESTORE-1/` (`test.lua`, `common.lua`, `child.lua`, `kill-after-pte.sh`,
  `guest.S`, `guest.bin`, `build.sh`). Run `bugs/run.sh R9-GOALRESTORE-1`. A bare-metal guest enables Sv39 with one
  gigapage PTE whose A bit is clear and performs one load. A child process loads the stored machine with `SHARING_ALL`
  and calls `collect_mcycle_root_hashes` with a period that keeps it inside one call; the script waits until the PTE
  write is visible in the shared RAM file, then sends SIGKILL. After the reload the PTE holds `0x2000004f`, but the
  `.dpt` does not mark the page, `verify_hash_tree()` fails ("page 0x80010000 (in RAM) is not marked dirty but is
  dirty"), the reloaded root differs from the root recomputed from the contents, and 200 mcycles later the reloaded
  machine and the recomputed copy still differ. The control, in which the child calls plain `run()` and is killed the
  same way, reloads consistently and agrees with the recomputation, so the cause is the collection accessor and not the
  kill method. The harness exits 2 if the control fails.
- **Scenario and reachability:** every state is ordinary and guest-reachable: a guest with PTEs whose A or D bit is
  clear triggers the write on its first access. The trigger is any process stop (kill, OOM, restart) during a
  collection on a machine loaded with `SHARING_ALL`; the window is a whole sampling period. The stored PRT player is
  not exposed: it clones `machine.revert` before it delivers an input (`doc/recipes/prt.lua:1405-1412`, `:1083-1090`),
  `revert_interrupted_input` (`:2636-2650`) restores that snapshot when its root matches `state.json`, and its pair
  directories are removed on reopen (`:2653-2676`). The only other collect call on the shared machine runs at a fixed
  point and executes no instruction. No path reuses a directory that was interrupted during collection, hence Medium; it
  would be Critical if one did and checked only the persisted root.
- **Possible solution:** make the collect accessor an `i_accept_dirty_pages` that marks the shared `.dpt` at the moment
  of a page-walk A/D write (the cost is a few byte writes per PTE update, which are rare), or mark the page before the
  store in `write_ram_uint64` for every accessor not covered by a write-TLB slot. As defense in depth, an "open" flag in
  the shared directory, set on a `SHARING_ALL` load and cleared on clean shutdown, can force `mark_pages_dirty` and a
  rebuild after an unclean stop, which also covers R7-FPUARCH-1 and R8-DYNPERSIST-1.
- **Risks:** a tool or a future player change that reopens a shared directory interrupted during collection and checks
  only its root would compute every later hash and proof from a tree that does not commit to the contents. Marking
  eagerly can only cause spurious rehashes, which are hash-neutral. No fix gives power-loss consistency without `msync`
  or `fsync` ordering.

---

## R10-MANLUA1-1

**The HTIF halt command ignores the `ihalt` availability mask, so a machine configured with `ihalt = 0` still halts
when the guest requests it**

- **Severity:** Medium (`AUDIT.md` section 8: an undocumented deterministic deviation from the manual, consistent
  across all paths). Confirmed by an independent disproving reviewer and reproduced by the orchestrator. Found in round
  10 (manual and promise checking); the MANARCH hunter reported the same defect (R10-MANARCH-3, merged by dedup).
- **Component and area:** emulator; the HTIF device.
- **Cited rules:** R7 (the manual is the specification of the devices); section 8 Medium. R2 holds: the native run, the
  uarch program and the log verifiers agree, so there is no soundness or completeness failure.
- **Location:** `src/htif-address-range.cpp:64-72` (`htif_halt` never reads `htif_ihalt`; the only reader is the MMIO
  read path at `:49-50`). Compare `htif_yield` (`:74-90`) and `htif_console` (`:93-121`), which gate on
  `iyield` and `iconsole`. Manual: `doc/README.md:7507-7509` ("Unavailable commands are silently ignored by the
  machine"); configuration field `processor.registers.htif.ihalt` at `:3212` (default `0x1` at `:3542`).
- **Defect:** `htif_halt` checks only that the command is halt and that data bit 0 is set, then sets `iflags_H`. With
  `ihalt = 0` the request must be a silent no-op and execution must continue.
- **Evidence and test:** `bugs/R10-MANLUA1-1/` (`test.lua`, `halt.S`, `link.ld`, `build.sh`; the guest is built at run
  time). Run `bugs/run.sh R10-MANLUA1-1`. A guest writes `tohost = 1` and spins. The control with `ihalt = 1` halts at
  mcycle 3. With `ihalt = 0` the native run still halts at mcycle 3 (`iflags_H = 1`, break reason halted) and so does the
  uarch path (8 `run_uarch` and `reset_uarch` rounds), with the same root hash as the native run. Expected: no halt.
- **Scenario and reachability:** a template made with the documented `ihalt = 0` is a valid template, and any guest
  instruction stream can write `tohost`. The deviation is the same on every path (the uarch program is compiled from the
  same C++, so the on-chain verifiers follow it too; that part was not run on-chain). Halting is a stall that a
  correctly designed application does not use, and A5 already excludes outputs from halted states, hence Medium.
- **Possible solution:** gate the halt like the other sub-devices:
  `cmd < 64 && ((read_htif_ihalt() >> cmd) & 1) != 0 && cmd == HTIF_HALT_CMD_HALT && (data & 1) != 0`, and ignore the
  request otherwise. Alternatively document `ihalt` as informational only or remove the field.
- **Risks:** the fix changes the state transition function (R13): the uarch program, its pinned pristine hash and the
  on-chain verifiers change together and must not be mixed with old deployments (A6). The default `ihalt = 0x1` is
  unaffected; a template created with `ihalt = 0` would stop halting and change its canonical trajectory.

---

## R11-FAMMASK-2

**Configured `mvendorid`, `marchid` and `mimpid` are accepted and never checked for newly created machines, although
the manual says they are checked at instantiation**

- **Severity:** Medium (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test,
  and reproduced by the orchestrator. Found in round 11 (family expansion). Version-mismatch detection is lost for
  machines created from a configuration.
- **Component and area:** emulator; machine configuration validation.
- **Cited rules:** R13, R7, section 8 Medium. Reviewer: R13; A6; THREAT_MODEL section 8 (manual/behavior contradiction
  on a security-relevant point; Medium: violates the manual without affecting the goal); section 2 'Valid template'
  (created from a configuration by operations the manual specifies).
- **Location:** src/machine.cpp:129-195 (init_processor never writes reg::mvendorid/marchid/mimpid),
  src/machine.cpp:199-211 (validate_processor_shadow compares the shadow, not the config),
  src/machine-config.cpp:205-215 (adjust_defaults keeps any value other than -1)
- **Defect:** The manual (doc/README.md:3355-3359) says users set mvendorid, mimpid and marchid in the config, 'which
  the emulator checks at instantiation to ensure the configuration matches the running emulator version', and that
  production code should hard-code them. adjust_defaults replaces only -1. init_processor writes every register field
  of the config into the shadow except these three; the shadow keeps the processor_state{} defaults, which equal the
  build constants. validate_processor_shadow then compares those defaults with the constants, a check that always
  passes. The config's values are never compared with anything. They stay in get_initial_config(), and machine::store
  writes them into config.json, while read_reg and the hashed shadow hold the build's values.
- **Evidence and test:** `bugs/R11-FAMMASK-2/` (`test.lua`). Run `bugs/run.sh R11-FAMMASK-2`. It fails while the bug
  is present. Observed: I ran it 3 times and it exited 1 each time with the same output:   marchid=12367 (build 22)
  accepted at creation: get_initial_config=12367, read_reg=22, config.json=12367, reload succeeded
  mvendorid=7161130726739634471 (build 7161130726739634464) accepted at creation:
  get_initial_config=7161130726739634471, read_reg=7161130726739634464, config.json=7161130726739634471, reload
  succeeded   mimpid=122 (build 23) accepted at creation: get_initial_config=122, read_reg=23, config.json=122, reload
  succeeded FAIL: cartesi.machine(config) accepts mvendorid/marchid/mimpid that do not match the build; the manual
  says they are checked at instantiation (R13 version-mismatch detection lost) FAIL R11-FAMMASK-2 (bug present, status
  1) Sanity checks passed first. Configs with the build's own IDs are accepted, and so are configs with -1. A failure
  there exits 2 as a harness error, so the exit 1 comes from the defect.
- **Scenario and reachability:** Reached deterministically on the documented template-creation path
  (cartesi.machine(config) / cm_create_new) by any host that follows the manual and hard-codes the IDs. No adversary
  or guest action is involved. It is host configuration data, so input senders and dishonest claimants cannot trigger
  it.
- **Possible solution:** In machine::init_processor, for a newly created processor, check the config's version
  registers unless r.skip_version_check is set: after adjust_defaults has turned -1 into the build constants, throw
  std::invalid_argument("marchid/mvendorid/mimpid mismatch, emulator version is incompatible") when
  p.registers.marchid != MARCHID_INIT, and the same for mvendorid and mimpid. Optionally, also normalize the stored
  config so that get_initial_config()/config.json always report the values in the shadow. The other option is to
  change the manual to say that the IDs are read-only and that the config values are ignored, but that drops the
  documented production safeguard.
- **Risks:** Issue risk: - Operators who hard-code the IDs as instructed get no refusal at creation. - Tooling that
  reads config.json or get_initial_config() to decide which emulator version a template belongs to is misled. Those
  files can advertise IDs that differ from the hashed state. - The goal is not broken, because content-hash comparison
  against the on-chain commitment and the stored-shadow check still catch a real mismatch. Fix risk: - Creation now
  throws for configs that worked before. Examples are configs copied from another build's config.json, or configs
  carrying stale IDs. - The check must apply only to newly created processors, so that a stored machine's config.json
  is not re-validated against values that are ignored anyway. Otherwise it can conflict with the shadow-based check
  and with skip_version_check. - The JSON-RPC/remote creation paths share the same code and need the same behavior, so
  that paths do not diverge.

---

## R11-FAMPERSISTA-1

**The native interpreter's page walk stores the PTE accessed/dirty update into shared RAM before marking the page
dirty, so a stop in between leaves a stale hash tree in a shared stored machine**

- **Severity:** Medium (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test,
  and reproduced by the orchestrator. Found in round 11 (family expansion). Reported by two hunters (FAMPERSISTB-1
  merged by dedup). Same root cause class as R8-DYNPERSIST-1 and R9-GOALRESTORE-1, at a different site: the native
  interpreter's page walk.
- **Component and area:** emulator; `write_ram_uint64` on the native `state_access` path (plain `run()`).
- **Cited rules:** R9, R2, section 8 Medium. Reviewer: R9; R2; section 8 Medium: persistence defects off the honest
  operator's path.
- **Location:** src/translate-virtual-address.hpp:62-77 (store at :70, mark at :74),
  src/translate-virtual-address.hpp:233-241 (A/D update call), src/state-access.hpp:479-481 (do_write_memory_word
  writes through the host pointer, no mark), src/state-access.hpp:567-568, src/i-accept-dirty-pages.hpp:29-40
- **Defect:** write_ram_uint64 first calls a.write_memory_word(faddr, pma_index, val), which for state_access is a raw
  aliased_aligned_write into the MAP_SHARED RAM file. Only afterwards does it call a.mark_dirty_page(paddr,
  pma_index), which sets the leaf and its ancestors in the shared .dpt. Nothing else records the change: the
  page-table page is not in a write-TLB slot, because a walk installs only a read or code entry for the target page.
  On reload, the .dpt and .dht (dense hash tree) files are trusted (memory-address-range.cpp:76-79). This is a
  different accessor and site from R9-GOALRESTORE-1, where the collect accessor defers the mark to the end of the
  period; R9's own control claimed plain run() was safe. It is also a different site from R8-DYNPERSIST-1, which
  covers the host API writers.
- **Evidence and test:** `bugs/R11-FAMPERSISTA-1/` (`test.lua`, `child.lua`, `kill.py`, `common.lua`, `guest.S`,
  `guest.bin`, `build.sh`). Run `bugs/run.sh R11-FAMPERSISTA-1`. It fails while the bug is present. Observed: I ran
  the test 4 times on feature/prt-audit. It failed with exit 1 every time, with identical output: "child killed right
  after the PTE store, at: cartesi::write_ram_uint64<cartesi::state_access> src/translate-virtual-address.hpp:74" -
  reloaded PTE 0x2000004f (the A bit is set in the shared RAM file) - reloaded root
  0x8a4273cfd24e555b16a5bea7edff040ebec8f1ff814739ecffed022f80457b00 - root recomputed with clear_hash_tree
  0x25f3934edecb72d6a91e0b2bc77899d4f2c643afda75167bdd76aecd536e9bf8 - verify_hash_tree false ("page 0x80010000 (in
  RAM) is not marked dirty but is dirty") - after 200 more mcycles: reloaded 0x04dcf617... vs recomputed 0x47b7f0b7...
  Final line: "FAIL: SIGKILL right after the page walk's A-bit store in plain run() left a SHARING_ALL stored machine
  whose persisted root ... differs from the root of its contents ...: write_ram_uint64 stores before mark_dirty_page
  (violates R9/R2)". The reloaded and recomputed roots agree (0x47b7f0b7... after +200 mcycles) and the test exits 0.
  So the failure comes from the store-to-mark window and from nothing else, and a fix that marks before storing would
  make the test pass.
- **Scenario and reachability:** The guest state is ordinary and reachable. Any PTE with A or D clear works (section 2
  presumes any guest-writable memory reachable, and Linux creates such PTEs routinely). Any API or CLI user that runs
  a machine loaded with SHARING_ALL hits the site with plain run(), through state_access. The trigger is a process
  stop (SIGKILL, OOM, crash) inside a window a few host instructions long. That window sits between
  aliased_aligned_write of the PTE (translate-virtual-address.hpp:70) and mark_dirty_page (:74). The PoC hits it
  deterministically with a gdb hardware watchpoint on the PTE byte in the MAP_SHARED RAM mapping. In practice the
  window is narrow, but each page walk that sets an A or D bit reopens it. The stored PRT player is not exposed: it
  runs inside an input only after stored_machine_pair:snapshot(), which calls clone_stored. After a crash,
  revert_interrupted_input restores machine.revert whenever the recorded boundary root matches it (prt.lua:2636-2650).
  After the input ends, the run has finished, so the mark has already landed before state.json records the boundary.
  So this is off the honest operator's path.
- **Possible solution:** In write_ram_uint64, when the accessor is an i_accept_dirty_pages (state_access,
  record_step_state_access), call a.mark_dirty_page(paddr, pma_index) before a.write_memory_word(faddr, pma_index,
  val). Marking a page dirty only forces a rehash, so doing it first is hash-neutral. The general invariant is "mark
  the shared dirty-page tree before any store to shared memory that no write-TLB entry covers". Audit the other
  untracked writers against it in the same pass, for example the write-TLB slot replacement order (mark the old page
  before the shadow slot is overwritten) and the host API writers. A more conservative alternative is to record a
  "possibly unclean" flag in the stored directory while a SHARING_ALL machine runs, and to reload with
  mark_pages_dirty when the flag is set.
- **Risks:** Risk of the issue: a CLI or API user who reloads a SHARING_ALL directory after a crash and trusts its
  root gets a root and proofs that do not commit to the contents. Every later hash from that machine is wrong. A
  protocol participant who did this outside the player's snapshot discipline could compute a wrong claim, but the
  stored PRT player is protected. Risk of the fix: almost none. If a crash lands between the new mark and the store,
  the page is spuriously marked dirty and only rehashed. The extra cost is a dirty-page-tree mark that already happens
  today, just earlier. Performance is unchanged. record_step_state_access marks the machine's tree, not the log, so
  the change does not alter any log or proof and touches no verifier.

---

## R11-FAMPERSISTA-2

**`replace_memory_range` discards the write-TLB dirty marks still pending against the replaced shared range, so the
stored hash tree no longer commits to its contents (no crash needed)**

- **Severity:** Medium (`AUDIT.md` section 8). Confirmed by an independent disproving reviewer, who reran the test,
  and reproduced by the orchestrator. Found in round 11 (family expansion). Unlike the other persistence findings this
  one is deterministic and needs no crash.
- **Component and area:** emulator; `replace_memory_range` on a `SHARING_ALL` machine.
- **Cited rules:** R9, R2, section 8 Medium. Reviewer: R9; R2; THREAT_MODEL section 8 Medium: persistence defects off
  the honest operator's path; section 2 Honest operator's path (storing and reloading).
- **Location:** src/machine.cpp:717-770 (m_ars.replace at :765, then only init_hot_tlb_contents at :769; no
  mark_write_tlb_dirty_pages before the old range is dropped), src/machine-address-ranges.cpp:656-680 (old range
  object destroyed at :674), src/machine.hpp:722-727 and src/machine.cpp:1611-1628 (a later eviction or destruction
  marks the slot's page through read_pma(pma_index), which now names the NEW range)
- **Defect:** A page stored through a write-TLB slot is recorded only by that slot. Its .dpt mark is deferred until
  mark_write_tlb_dirty_pages runs, which happens in update_hash_tree, store, ~machine, shadow overwrite, or eviction
  in write_verified_tlb or write_unverified_tlb. replace_memory_range swaps in the new range without first flushing
  those pending marks into the old range's dirty-page tree. Afterwards, every flush of the slot (sfence.vma, satp or
  prv changes, slot replacement, ~machine) resolves pma_index to the replacement range, marks the page there (a
  spurious mark), and the mark for the old range is lost for good. If the old range was loaded SHARING_ALL, its .bin
  in the stored directory already holds the guest's bytes, while its .dpt and .dht still show the previous clean hash.
- **Evidence and test:** `bugs/R11-FAMPERSISTA-2/` (`test.lua`, `guest.S`, `build.sh`, `guest.bin`). Run `bugs/run.sh
  R11-FAMPERSISTA-2`. It fails while the bug is present. Observed: I ran the test 3 times and got the same result each
  time: exit 1, with identical hashes on every run. - Defect scenario: the reloaded directory's flash word is
  0x1122334455667788. Its stored root is 0x450f8cff8a629ede74e9c1043a9b6a50bdf61b52cf154f20f02e3d238af3d19a, but the
  root recomputed with clear_hash_tree=true is 0x04cec1c810065f2d966aa89ba54b08e17f17ffdca588e4115b50fd0f5f1af2aa.
  verify_hash_tree reports 'page 0x80000000000000 (in flash drive 0) is not marked dirty but is dirty' and returns
  false. - Control scenario: identical except that get_root_hash() is called before replace_memory_range, which
  flushes the pending marks. Stored and recomputed roots both equal 0x04cec1c8... and verify is true. - Printed line:
  "FAIL: after replace_memory_range on a SHARING_ALL machine, the stored directory's hash tree no longer commits to
  its flash contents (pending write-TLB dirty mark lost) ...".
- **Scenario and reachability:** The test is deterministic and needs no crash, only documented API calls: store D,
  load(D, SHARING_ALL), get_root_hash, run, replace_memory_range on the flash range, run (the guest executes
  sfence.vma), destroy, then reload D. I ran bash bugs/run.sh R11-FAMPERSISTA-2. The control scenario passes: it
  flushes the dirty marks with get_root_hash before the replace, and then reloaded == recomputed == 0x04cec1c8... and
  verify_hash_tree is true. The defect scenario fails. D's flash file holds 0x1122334455667788, but the reloaded root
  is 0x450f8cff... while the root recomputed from contents is 0x04cec1c8..., and verify_hash_tree reports 'page
  0x80000000000000 (in flash drive 0) is not marked dirty but is dirty'. The hashes quoted in the candidate text
  (0x9d5c..., 0xbdd1...) differ from what the shipped test prints, but the mechanism and the verdict are the same. The
  trigger is off the honest operator's path. The PRT player, bridge and referee model (doc/recipes/prt*.lua,
  game-*.lua) never call replace_memory_range. The CLI calls it only at startup (src/cartesi-machine.lua:3252-3255),
  before any run in that process, when no write-TLB marks are pending: the stored snapshot already has them flushed,
  because store calls mark_write_tlb_dirty_pages.
- **Possible solution:** In machine::replace_memory_range, call mark_write_tlb_dirty_pages() before
  m_ars.replace(replacement), after the validation and while the old range is still installed. That flushes every
  pending write-TLB mark into the dirty-page trees of the ranges the slots actually refer to. Optionally, also mark
  the hot write-TLB entries clean or re-verify them, so that later flushes do not mark the new range spuriously
  (harmless, since a new range starts all dirty). Then call init_hot_tlb_contents() as today. Apply the same
  flush-before-drop rule to any other path that destroys or swaps an address range while write-TLB slots may still
  point into it. Add a regression test equivalent to bugs/R11-FAMPERSISTA-2.
- **Risks:** Risk of the issue: a host that runs a SHARING_ALL (or shared-backing-store) machine and then replaces a
  range mid-run leaves a stored directory whose root does not commit to its contents. Every later hash or proof
  computed from that directory without clear_hash_tree is wrong, and the stale page is never re-hashed until it is
  written again. This is silent corruption of a snapshot the emulator wrote, but it is off the PRT honest operator's
  path, so the goal of section 1 is not affected. Risks of the fix: - mark_write_tlb_dirty_page can throw on a corrupt
  TLB. It must run before any mutation, so that replace_memory_range keeps strong exception safety and the throw does
  not leave a half-replaced machine. - The flush adds only O(TLB_SET_SIZE) work per replace. - It must not change any
  hashed state. It only touches dirty-page bookkeeping, so the canonical hashes are unchanged and no protocol-version
  (R13) impact is expected.
