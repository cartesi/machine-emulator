# Bugs

Confirmed issues of the PRT audit, ordered by severity. Severities and rules follow `THREAT_MODEL.md`. The process
and every rejected candidate are in `AUDIT_REPORT.md`. Run a test with `bugs/run.sh <ID>`; it fails while the bug is
present.

| ID | Title | Component | Cited rules | Severity |
|---|---|---|---|---|
| [R1-VERIFIER-1](#r1-verifier-1) | Uarch step verifier aborts the process on a relayed log against a fabricated before-state | emulator (uarch step verifier), PRT referee model | Section 4, R10, R3, R2, section 1 completeness, section 7 | Critical |
| [R1-TRANSITIONS-1](#r1-transitions-1) | Uarch computation-hash builder's fast reset restores only dirtied uarch-RAM words | emulator (uarch computation-hash builder) | R2, R13, R5, section 2 transition form | High |
| [R1-ARCH-1](#r1-arch-1) | CLINT `mtimecmp`-to-cycle conversion wraps, raising spurious timer interrupts (and none for `mtimecmp == 0`) | emulator (CLINT, timer interrupts) | R7, section 8 Medium | Medium |
| [R1-ARCH-2](#r1-arch-2) | Misaligned SC.W/SC.D without a matching reservation fails silently instead of trapping | emulator (atomics, LR/SC) | R7, section 8 Medium | Medium |

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
