# R7-MANCLIROLL-1: a host I/O error inside a stored-mode commit makes the CLI delete the O2-guaranteed directory

Component: `cartesi-machine --revert-mode=stored` (`src/cartesi-machine.lua`, `revert_stored.__index:commit`,
`revert_stored.__index:revert`, `revert_stored:__close`). Role: Support (the CLI).

## What happens

`commit()` destroys the machine, syncs `machine` (from then on O2 guarantees it, and it holds the newly accepted
state), clones it to `machine.revert.tmp` and syncs that, removes the old `machine.revert`, sets
`self.backup_directory = nil`, and renames `.tmp` to `.revert`. If anything after the removal starts fails with a
host I/O error, the error leaves `commit()` with `snapshot_taken` still true, so the to-be-closed `backup` runs
`__close(err)` -> `revert()`, which does `m:remove_stored(machine)` first and only then
`m:clone_stored(self.backup_directory, machine)`. That clone fails (`bad argument #1 to 'clone_stored' (string
expected, got nil)` or a missing file of the half-removed backup) after the synced `machine` is already gone.

## What the test asserts

`test.sh` runs the manual's stored-mode command (doc/README.md "Rolling Cartesi Machines directly from storage") on
the harness `baremetal-template` with two accepted inputs, first without a fault (control, must succeed), then
twice with an `LD_PRELOAD` shim (`ioshim.c`) that makes one call fail with `EIO` right after input 0 is accepted:

* **rename**: `renameat2(machine.revert.tmp -> machine.revert)` in the commit of input 0;
* **unlink**: the 2nd `unlink()` of a file under `machine.revert/` (the removal of the old backup in that commit).

* **interrupt** (added by the reviewer; no I/O fault): the shim raises `SIGINT` (an operator's Ctrl-C) at the
  2nd `unlink()` under `machine.revert/` and lets every call succeed. `lua5.4` turns the signal into an
  `interrupted!` error when `remove_stored` returns, inside the commit of input 0.

The CLI is not killed; it sees the error and runs its own cleanup. `check.lua` then requires, for each case, that
EITHER the `machine` directory, which O2 guaranteed with the state after input 0 when the fault hit, still loads
with that state (or the later committed state), OR the manual's recovery rule applied to the names left on disk
selects a directory that loads with a committed state (initial, after input 0, or after input 1). States are
computed independently from the template; roots are checked after rebuilding the hash tree.

Requirement (THREAT_MODEL.md):

* section 4: "A host fault, such as a full disk or an output channel that refuses a write, may stop the honest
  operator, but the emulator must never turn one into a wrong hash, a wrong proof, or a directory that O2
  guarantees but that later loads as a different state."
* section 5: "O1 and O2 bind the emulator too. The tools and reference implementations that ship with it must
  follow them ... A defect that defeats the rebuild itself, or that damages a directory while O2 guarantees it, is
  not excused by them."
* R4: "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim."
* Manual: "`machine.revert` always holds a synced copy of the last committed state."

## Run

```sh
bugs/run.sh R7-MANCLIROLL-1      # needs gcc, the in-tree build and bugs/harness/work/configs/baremetal-template
```

About 10 s (three cases). Temporary files go to a `mktemp -d` directory that is removed at exit.

## Expected output on audit/prt2 (exit 1)

```
== case rename: ...
    ioshim: failing renameat2 machine.revert.tmp with EIO
    lua5.4: .../cartesi-machine.lua:3926: bad argument #1 to 'clone_stored' (string expected, got nil)
    machine:            absent
    machine.revert:     absent
    machine.revert.tmp: absent
  case rename: BUG
== case unlink: ...
    ioshim: failing unlink machine.revert/0000000000000000-8000.dht with EIO
    machine:            absent
    machine.revert:     present, does not load: unable to open backing file ...
    machine.revert.tmp: present, root 1fd4a350... (after input 0)
  recovery rule: machine.revert exists -> resume from machine.revert; yields a committed state: false
  case unlink: BUG
== case interrupt: ...
    ioshim: raising SIGINT at unlink machine.revert/0000000000000000-8000.dht
    lua5.4: .../cartesi-machine.lua:3926: unable to read file 'machine.revert/config.json': open() failed: ...
    machine:            absent
    machine.revert:     absent
    machine.revert.tmp: present, root 1fd4a350... (after input 0)
  recovery rule: only machine.revert.tmp exists -> resume from machine; yields a committed state: false
  case interrupt: BUG
run.sh: R7-MANCLIROLL-1: exit 1 (bug present)
```

In the interrupt case the documented rule resumes from the deleted `machine` and discards `machine.revert.tmp`,
the only remaining copy of the committed state.

In the unlink case the only intact copy (`machine.revert.tmp`) is the one the documented rule discards.

## Checks done while writing the test (not part of it)

* With a patched copy of the CLI that clears `snapshot_taken` right after `sync_stored(machine)` and keeps
  `machine.revert.tmp` after a failed rename, both cases pass and the test exits 0.
* With a patched copy that applies the rename-before-remove change of R5-INVSTORE-2 (rename the old backup
  away, rename `.tmp` into place, then remove the old one) but leaves `revert()` as it is, the rename case still
  fails (all three directories gone), so this is distinct from R5-INVSTORE-2.
