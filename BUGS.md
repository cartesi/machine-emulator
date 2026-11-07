# Bugs

Confirmed issues of the PRT audit, ordered by severity. Severities and rules follow `THREAT_MODEL.md`. The process
and every rejected candidate are in `AUDIT_REPORT.md`. Run a test with `bugs/run.sh <ID>`; it fails while the bug is
present.

| ID | Title | Component | Cited rules | Severity |
|---|---|---|---|---|
| [R1-GUESTTOOLS-1](#r1-guesttools-1) | Honest PRT player aborts for good when a guest yield's DATA exceeds the transmit buffer | PRT player and bridge (yield handling) | R4, section 1 completeness, section 2 reachable state, section 4, A7 | Critical |
| [R1-PLAYER-1](#r1-player-1) | Relaunched honest bridge abandons its own claim when an adversary joined that commitment first | PRT player and bridge (claim binding after restart) | R4, A7, section 1 completeness, section 7 | Critical |
| [R1-PLAYER-2](#r1-player-2) | Eight-entry input-boundary cache makes reaching a disputed position cost about n/5 whole inputs | PRT player and bridge (machine cache, replay cost) | R12, A7, R4, section 1 completeness, section 7 | Critical |
| [R1-PLAYER-3](#r1-player-3) | Player reads the previous epoch's seal with one unpaged `eth_getLogs` and crash-loops once the chain outgrows the node's range limit | PRT player and bridge (epoch discovery) | R4, A7, section 4, section 1 completeness | Critical |
| [R1-PLAYER-5](#r1-player-5) | Next-epoch inputs run between two ticks of the current dispute, so an input flood delays honest responses past the clocks | PRT player and bridge (scheduling, deadlines) | R4, A7, R12, section 1 completeness, section 7 | Critical |
| [R1-REFEREE-1](#r1-referee-1) | A late Sybil re-post of the honest claim cuts the honest claim's clock to one block | PRT referee model (tournament joining, clocks) | A7, section 1, section 2 honest claim, section 7, the manual's clock rule | Critical |
| [R1-REFEREE-2](#r1-referee-2) | Output proofs are not range-checked: every output is accepted again at index i - 2^63 | PRT referee model (output verification), `cartesi.hash-tree` | A5, section 1 soundness, section 4, R11, R9 | Critical |
| [R1-ROBUST-1](#r1-robust-1) | Honest player keeps every tx-output payload of an input in memory, so a guest drives its memory up without bound | PRT player and bridge (output collection) | R8, R12, R4, A7, section 1 completeness, section 4 | Critical |
| [R1-VERIFIER-1](#r1-verifier-1) | Uarch step verifier aborts the process on a relayed log against a fabricated before-state | emulator (uarch step verifier), PRT referee model | Section 4, R10, R3, R2, section 1 completeness, section 7 | Critical |
| [R1-PLAYER-4](#r1-player-4) | Epoch listeners fetch, keep and re-sort every InputBox log of every application | PRT player and bridge (input observation) | Section 4, R12, A7, R4, section 7 | High |
| [R1-ROBUST-3](#r1-robust-3) | Each guest automatic yield costs the honest player a host-API round trip, a guest-chosen constant-factor slowdown | PRT player and bridge (run loop, computation-hash collection) | R12, A7, section 8 High | High |
| [R1-TRANSITIONS-1](#r1-transitions-1) | Uarch computation-hash builder's fast reset restores only dirtied uarch-RAM words | emulator (uarch computation-hash builder) | R2, R13, R5, section 2 transition form | High |
| [R1-ARCH-1](#r1-arch-1) | CLINT `mtimecmp`-to-cycle conversion wraps, raising spurious timer interrupts (and none for `mtimecmp == 0`) | emulator (CLINT, timer interrupts) | R7, section 8 Medium | Medium |
| [R1-ARCH-2](#r1-arch-2) | Misaligned SC.W/SC.D without a matching reservation fails silently instead of trapping | emulator (atomics, LR/SC) | R7, section 8 Medium | Medium |
| [R1-ARCH-3](#r1-arch-3) | Page walk ignores PMA failures on PTE accesses | emulator (address translation) | R7, section 8 Medium | Medium |
| [R1-ARCH-4](#r1-arch-4) | S-mode `sip` writes can set and clear the read-only STIP and SEIP bits | emulator (supervisor interrupt CSRs) | R7, section 8 Medium | Medium |
| [R2-VERIFIER-2](#r2-verifier-2) | Send-cmio-response verifier accepts read accesses carrying unchecked `written`/`written_hash` fields | emulator (input-delivery log verifier) | R3, R11, section 4, section 8 Medium | Medium |

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
