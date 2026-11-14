## R7-MANCLIROLL-1

**Title.** In `cartesi-machine --revert-mode=stored`, an error raised inside a commit after the removal of the old
`<directory>.revert` starts (a SIGINT, or a host I/O error) runs the CLI's own error-path revert. That revert deletes
the synced, O2-guaranteed `<directory>` before it checks that a backup exists. The documented recovery rule then has
no intact committed state to resume from.

**Severity.** Medium (preferred). Low if deleting a guaranteed directory breaks no rule while the epoch's template
stays a guaranteed restart point. For the host-I/O-error triggers alone, the host-fault exclusion read literally makes
them Out of scope. The SIGINT trigger is not a host fault.

### Problem

`revert_stored.__index:commit` runs after `backup:snapshot()` has set `snapshot_taken = true` (in
`run_advance_state_input`, the accepted branch calls `backup:commit()`). The commit does these steps:

1. Destroys the machine and syncs `machine`. From here on O2 guarantees `machine`, and it holds the newly accepted
   state.
2. Clones `machine` to `machine.revert.tmp` and syncs the clone.
3. Calls `remove_stored(machine.revert)` and sets `self.backup_directory = nil`.
4. Renames `.tmp` to `machine.revert`. If the rename fails, it calls `remove_stored(machine.revert.tmp)` and
   rethrows.
5. Sets `self.backup_directory`, loads `machine` again, and only then clears `snapshot_taken`.

Suppose an error leaves `commit()` during or after step 3. The trigger can be a SIGINT, which `lua5.4` raises as
`interrupted!` once `remove_stored` returns, or an `EIO`, `ENOSPC` or `EDQUOT` from `unlink` or `rename`. Then
`snapshot_taken` is still true, so the to-be-closed `backup` runs `revert_stored:__close(err)`, which calls
`revert()`. `revert()` runs `m:remove_stored(machine)` unconditionally, and only then calls
`m:clone_stored(self.backup_directory, machine)`. The backup directory is nil, removed or half-removed, so the clone
fails. By then the synced `machine` is already gone. Three outcomes follow:

- **SIGINT during the removal of the old backup.** `machine` and `machine.revert` are gone, and only
  `machine.revert.tmp` holds the committed state. The documented rule says "If `machine.revert` is missing but
  `machine.revert.tmp` exists, ... `machine` holds that state and `machine.revert.tmp` can be discarded". That
  points at the deleted `machine`, and it tells the operator to discard the only intact copy.
- **The rename fails.** `machine`, `machine.revert` and `machine.revert.tmp` are all gone. The rule says "If neither
  exists, the command stopped before its first commit", which is false here.
- **An unlink of the old backup fails.** `machine` is gone, and `machine.revert` is half-removed and does not load.
  The rule resumes from that partial `machine.revert` and discards the intact `.tmp`.

The manual's promise "`machine.revert` always holds a synced copy of the last committed state" fails in all three
cases. The tool's own handling of a stop damages a directory while O2 guarantees it. Its documented restart then
cannot resume from the guaranteed copy of the committed state, so the operator has to re-run the epoch from the
template. No wrong hash results, and every failure is loud.

### Component, role and area

- **Component:** the `cartesi-machine` CLI (`src/cartesi-machine.lua`) in stored revert mode, together with its
  documented recovery rule.
- **Role:** Support. The AUDIT.md table says: "The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI,
  ... | Support. No production deployment runs the player, the bridge or the CLI." The CLI computes claims (outputs
  Merkle roots, computation hashes), so it stands in for the honest operator.
- **Emulator API:** `remove_stored`, `clone_stored`, `sync_stored` and `rename_stored` behave as documented and do
  not show the defect.
- **Area:** the CLI's snapshot/commit/revert state machine on its error path.

### Location

- `src/cartesi-machine.lua`:
  - `revert_stored.__index:commit` (lines 3893-3918). `snapshot_taken` stays true until line 3917, after
    `remove_stored(self.backup_directory)` (line 3905), `self.backup_directory = nil` (line 3906) and the failed-rename
    branch (lines 3909-3913).
  - `revert_stored.__index:revert` (lines 3920-3929), which calls `remove_stored(machine)` before
    `clone_stored(self.backup_directory, ...)`.
  - `revert_stored:__close` (lines 3941-3943).
  - The caller: `backup:snapshot()` (line 4707), then `backup:commit()` (line 4725).
  - The `--revert-mode` help (lines 163-175).
- `doc/README.md`, lines 2522-2541: the stored-mode description and the recovery rule.

### Evidence and test

`bugs/R7-MANCLIROLL-1/` contains these files:

- `test.sh`: the driver.
- `ioshim.c`: an `LD_PRELOAD` shim. It fails one chosen `renameat2()` or `unlink()` with `EIO`, or, with
  `FAIL_SIGINT`, raises SIGINT at that call and lets the call succeed.
- `check.lua`: inspects what is left on disk and applies the documented rule.
- `README.md`.

**How the test runs.**

1. `test.sh` builds the shim.
2. It runs the manual's stored-mode command on `bugs/harness/work/configs/baremetal-template` with two accepted
   inputs:
   `--revert-mode=stored --load=machine,clone:<template>/machine,sharing:all --cmio-advance-state=input_file_index_begin:0,input_file_index_end:2`.
3. It runs a control without a fault, which must succeed.
4. It runs three fault cases. Each fires inside input 0's commit, once `input-0-outputs-merkle-root.bin` exists:
   - **rename:** `renameat2(machine.revert.tmp -> machine.revert)` fails with `EIO`.
   - **unlink:** the 2nd `unlink` under `machine.revert/` fails with `EIO`.
   - **interrupt:** SIGINT is raised at the 2nd `unlink` under `machine.revert/`, and every call succeeds.
5. `check.lua` computes the committed states independently from the template: initial `428a6bb8...`, after input 0
   `1fd4a350...`, and after input 1 `c8bf66d5...`. Each case passes only if one of these holds:
   - `machine`, which was O2-guaranteed with the state after input 0 when the fault hit, still loads with a later
     committed state.
   - The documented rule selects a directory that loads, with its cached root equal to its rebuilt root, and holds a
     committed state.

Run it with `bugs/run.sh R7-MANCLIROLL-1` (about 8 s). On audit/prt2 it prints the following (abridged):

```
== case rename: ...
    ioshim: failing renameat2 machine.revert.tmp with EIO
    lua5.4: .../cartesi-machine.lua:3926: bad argument #1 to 'clone_stored' (string expected, got nil)
    machine: absent / machine.revert: absent / machine.revert.tmp: absent
  case rename: BUG
== case unlink: ...
    ioshim: failing unlink machine.revert/0000000000000000-8000.dht with EIO
    machine: absent
    machine.revert: present, does not load: unable to open backing file '.../machine.revert/0000000000000000-8000.bin' ...
    machine.revert.tmp: present, root 1fd4a350... (after input 0)
  recovery rule: machine.revert exists -> resume from machine.revert; yields a committed state: false
  case unlink: BUG
== case interrupt: ...
    ioshim: raising SIGINT at unlink machine.revert/0000000000000000-8000.dht
    lua5.4: .../cartesi-machine.lua:3926: unable to read file 'machine.revert/config.json': open() failed: No such file or directory
    machine: absent / machine.revert: absent
    machine.revert.tmp: present, root 1fd4a350... (after input 0)
  recovery rule: only machine.revert.tmp exists -> resume from machine; yields a committed state: false
  case interrupt: BUG
run.sh: R7-MANCLIROLL-1: exit 1 (bug present)
```

**Runs and checks.**

- The prover wrote the rename and unlink cases. The reviewer added the interrupt case (the `FAIL_SIGINT` mode of
  `ioshim.c`), because it triggers the same code path without a host fault, and made `check.lua`'s message generic.
- The reviewer ran the test twice, and it exited 1 both times with the same output.
- The reviewer then ran `test.sh` against a scratch copy of the CLI whose `commit` sets `self.snapshot_taken = false`
  right after `m:sync_stored(self.machine_directory)`. With that copy, all three cases pass and the test exits 0:
  `machine` survives with root `1fd4a350...`.
- The prover reported that the rename case still fails with R5-INVSTORE-2's rename-before-remove fix applied.
- All agents ran on Opus 5.5 (no fallback).

### Trigger and reachability

The trigger is an error raised inside a commit while the old `machine.revert` is being removed, or between that
removal and the end of the rename. Two kinds of event raise it:

- an operator's interrupt (SIGINT, Ctrl-C, as delivered by a terminal or a supervisor), which the shipped launcher
  (`lua5.4 cartesi-machine.lua`) turns into a Lua error;
- a host I/O error from `unlink` or `rename`.

No input or adversary is needed. Every stored-mode run removes the old backup at every commit after the first, which
means after every accepted input, with any valid template and any input sequence. On a Linux machine,
`remove_stored` unlinks dozens of files and makes the removal durable, so the window is not instantaneous.

### Rating

1. **Out of scope.** Three exclusions were checked:
   - "Host faults, such as a full disk, as long as the emulator does not turn them into a wrong hash, a wrong proof,
     or a directory that O2 guarantees but that later loads as a different state." Read literally, this covers the
     rename and unlink cases: deletion is none of the three listed outcomes. It does not cover the interrupt case,
     because a SIGINT is not a host fault.
   - "Defects that need the honest operator to reload a stored directory that O2 does not guarantee". The defect does
     not need such a reload. `machine` was guaranteed when the CLI deleted it: it had been synced after its machine
     was destroyed, and it was not used afterwards.
   - O2's "leaves every stored directory it was writing or sharing in an unspecified state" does not excuse the
     deletion either. Section 5 says: "A defect that ... damages a directory while O2 guarantees it, is not excused
     by them."

   So the defect is in scope through the interrupt trigger.
2. **Role.** The CLI is Support (AUDIT.md table, quoted above). Section 3 says: "A defect that only a support
   component shows is Medium when it would rate High or Critical in the role the component stands in for, such as
   ... the honest operator for an implementation of an operator or a tool that computes claims." The clause covers
   the CLI, which computes outputs Merkle roots and computation hashes. The emulator's stored-machine functions do
   not show the defect.
3. **High and Medium cases.** The candidate case is "A persistence operation that fails loudly, without a wrong hash
   or damage to a directory that O2 guarantees, in an uncommon host setup that the manual documents, or while cleaning
   up after a stop." It does not fit. The CLI's cleanup after the interrupt deletes `machine`, which is damage to a
   directory that O2 guarantees. No High case fits.
4. **Critical (in the stand-in role).** "Restarting after a stop (O2)" is part of the "Honest operator's path".
   - R4 requires: "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim."
   - O2 requires: "The operator discards those directories and resumes from a guaranteed one, such as the snapshot
     taken before the current input."
   - Section 5 adds: "O1 and O2 bind the emulator too. The tools and reference implementations that ship with it
     must follow them".

   The tool's stop handling deletes the guaranteed snapshot of the committed state. Its documented rule then resumes
   from a deleted or partial directory, and it discards `machine.revert.tmp`, the remaining guaranteed copy. That
   violates O2 as it binds the tool, at a reachable state and on the honest operator's path, which is Critical in the
   honest-operator role. The support rule therefore gives **Medium**, and step 2 caps a support-only defect at Medium.
   The manual's "`machine.revert` always holds a synced copy of the last committed state" is also contradicted.
   Section 8 says such a contradiction "takes the severity it would have if the manual were right".

**Other readings.**

- **Low.** Starting over from the epoch's template, which the CLI never touches, is still "a directory that O2
  guarantees". On this reading R4 can be met at the cost of re-running the epoch, deleting a guaranteed directory
  breaks no listed rule, and the defect is Low. The deciding fact is whether section 5's "damages a directory while
  O2 guarantees it" marks a violation on its own, or only removes an excuse.
- **Out of scope.** The host-I/O-error cases alone are Out of scope under the literal host-fault exclusion. They would
  be Medium only if the exclusion's protected outcomes were read to include damage to a guaranteed directory, which
  the Medium case's wording "without ... damage to a directory that O2 guarantees" suggests.

### Possible solution and risks

Make the commit stop counting as an open snapshot once `machine` is synced: set `self.snapshot_taken = false`
immediately after `m:sync_stored(self.machine_directory)`. After that point the accepted state is durable, and
reverting it is never correct. Also make `revert()` check that `self.backup_directory` exists and loads before it
removes `machine`, or clone the backup to a temporary name first and rename it into place. On a failed rename, keep
`machine.revert.tmp` instead of removing it.

Combine this with R5-INVSTORE-2's rename-before-remove change, so that a partial `machine.revert` never exists, and
update the manual's rule and its Lua excerpt to match.

Risks of the fix:

- After an error past the sync, the process exits with `machine` holding the accepted state but not loaded. Callers
  that expect a reverted machine on any error must not rely on that.
- `machine.revert.tmp` may be left behind. The rule already says it is discarded in every case.

### Risk of not fixing it

No production deployment runs the CLI, so the goal is not directly exposed. An operator or integrator who interrupts
a stored-mode run, or whose disk returns an I/O error, during a commit loses the synced copy of the last committed
state. If they follow the documented recovery rule, they also discard the only remaining copy and must re-run the
epoch from the template. Node implementations that copy this snapshot/commit/revert pattern inherit a stop handler
that deletes guaranteed directories.

Mitigation until fixed:

- Do not interrupt stored-mode runs with SIGINT.
- After any abnormal exit, check `machine.revert.tmp` for the committed state before discarding anything.
