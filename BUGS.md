# Bugs

Confirmed issues of the PRT audit, ordered by severity. Severities and rules follow `THREAT_MODEL.md`. The process
and every rejected candidate are in `AUDIT_REPORT.md`. Run a test with `bugs/run.sh <ID>`; it fails while the bug is
present.

| ID | Title | Component | Cited rules | Severity |
|---|---|---|---|---|
| [R1-GUESTTOOLS-1](#r1-guesttools-1) | Honest PRT player aborts for good when a guest yield's DATA exceeds the transmit buffer | PRT player and bridge (yield handling) | R4, section 1 completeness, section 2 reachable state, section 4, A7 | Critical |
| [R1-PLAYER-1](#r1-player-1) | Relaunched honest bridge abandons its own claim when an adversary joined that commitment first | PRT player and bridge (claim binding after restart) | R4, A7, section 1 completeness, section 7 | Critical |
| [R1-PLAYER-3](#r1-player-3) | Player reads the previous epoch's seal with one unpaged `eth_getLogs` and crash-loops once the chain outgrows the node's range limit | PRT player and bridge (epoch discovery) | R4, A7, section 4, section 1 completeness | Critical |
| [R1-VERIFIER-1](#r1-verifier-1) | Uarch step verifier aborts the process on a relayed log against a fabricated before-state | emulator (uarch step verifier), PRT referee model | Section 4, R10, R3, R2, section 1 completeness, section 7 | Critical |
| [R1-TRANSITIONS-1](#r1-transitions-1) | Uarch computation-hash builder's fast reset restores only dirtied uarch-RAM words | emulator (uarch computation-hash builder) | R2, R13, R5, section 2 transition form | High |
| [R1-ARCH-1](#r1-arch-1) | CLINT `mtimecmp`-to-cycle conversion wraps, raising spurious timer interrupts (and none for `mtimecmp == 0`) | emulator (CLINT, timer interrupts) | R7, section 8 Medium | Medium |
| [R1-ARCH-2](#r1-arch-2) | Misaligned SC.W/SC.D without a matching reservation fails silently instead of trapping | emulator (atomics, LR/SC) | R7, section 8 Medium | Medium |
| [R1-ARCH-3](#r1-arch-3) | Page walk ignores PMA failures on PTE accesses | emulator (address translation) | R7, section 8 Medium | Medium |
| [R1-ARCH-4](#r1-arch-4) | S-mode `sip` writes can set and clear the read-only STIP and SEIP bits | emulator (supervisor interrupt CSRs) | R7, section 8 Medium | Medium |

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
