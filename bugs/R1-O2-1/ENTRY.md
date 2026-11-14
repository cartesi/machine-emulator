## R1-O2-1

**Title.** After a power loss, the PRT stored player restarts from its unsynced backup clone (`machine.revert`),
discards the synced epoch machine, and trusts the clone's cached hash tree, recording wrong root hashes.

**Severity.** Medium

### Problem

`stored_machine_pair_methods:commit` in `doc/recipes/prt.lua` refreshes the backup of the epoch machine after
`state.json` already records the new input boundary: it removes `machine.revert`, clones the (synced) epoch machine
into `machine.revert` under that final name, and only then syncs it. If the process stops between the clone and its
sync (power loss), `machine.revert` is a directory that was being written when its process stopped, so O2 does not
guarantee it, while the epoch machine `machine`, synced by `commit_epoch_state` before `state.json` was written, is
guaranteed.

On relaunch, `revert_interrupted_input` prefers the backup: if the backup's contents, rehashed with
`clear_hash_tree`, match the root hash in `state.json`, it removes the guaranteed epoch machine and replaces it with
a clone of the unsynced backup. `reopen_epoch_directory` then loads that clone with `SHARING_ALL` and without
`clear_hash_tree` (`new_stored_machine`), so the player keeps using cached hash-tree data that was never synced. The
contents check cannot detect damage to that cached data, and the load check compares only the cached root. The
player then advances, and as pages change their stale leaf hashes enter the root: it silently records root hashes
(and would build computation hashes and proofs) that are not the content hashes of its machine. An honest operator
built like this would commit a wrong claim and lose its dispute, which is a completeness failure of section 1 in
the role the player stands in for.

### Component, role and area

The PRT player in `doc/recipes` (`prt.lua`, stored player and its epoch directory, crash recovery). AUDIT.md table:
"The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI, and the Lua helper libraries ... | Support.
No production deployment runs the player, the bridge or the CLI." It stands in for the honest operator. The
emulator's `clone_stored`, `sync_stored` and `load` behave as documented; no component in another role shows the
defect.

### Location

- `doc/recipes/prt.lua`, `stored_machine_pair_methods:commit` (clone into `<directory>.revert` under its final
  name, sync afterwards; around lines 1137-1150), called by `run_next_input` right after `commit_epoch_state`
  (around lines 2268-2270).
- `doc/recipes/prt.lua`, `revert_interrupted_input` (around lines 2864-2880): picks the backup by a content rehash
  (`get_stored_root_hash`, lines 2850-2861), removes the synced epoch machine, clones the backup without a sync.
- `doc/recipes/prt.lua`, `reopen_epoch_directory` (around lines 3066-3102) and `new_stored_machine` (lines
  1007-1012): load the epoch machine with `SHARING_ALL` and without `clear_hash_tree`.

### Evidence and test

`bugs/R1-O2-1/` contains:

- `test.lua`: runs `doc/recipes/prt.lua`'s stored player, loaded unchanged as a module, in child processes on the
  harness `baremetal-template` configuration, with two advance inputs. (1) Control: a fresh epoch directory gets
  inputs 0 and 1 without a stop and records root R. (2) Crash: a fresh epoch directory gets input 0; the power loss
  is modelled right before the player syncs the not-yet-synced clone of the epoch machine (`machine.revert`): one
  4 KiB block of that clone's RAM `.dht` (leaf hashes of RAM pages 0..127) reads back as zeros, and the process
  exits with `os.exit` without cleanup. Directories already synced are untouched. (3) Relaunch: a new process opens
  the same epoch directory and is delivered inputs 0 and 1, as a restarted listener does; it records root R'. The
  test asserts R' == R and also prints the relaunched machine's content hash rebuilt with `clear_hash_tree`.
- `player.lua`: the driver (`run` and `crash` modes; `crash` wraps `clone_stored`/`sync_stored` to model the loss).
- `README.md`: description of the mechanism and the test.

Run `bugs/run.sh R1-O2-1` (about 10 s, about 100 MB in a `mktemp -d` directory that it removes). On audit/prt2 it
exits 1, deterministically (re-run twice by the reviewer), printing:

```
POWER LOSS before syncing /tmp/r1-o2-1.XXXXXX/crashed/machine.revert
uninterrupted player, root after input 1:          0x45dfda061ef00a368c1950bbfdca9bd0b2c6a9c0270b63d0e16e3db3dec0cba1
relaunched player, root it records after input 1:  0x2ff8357c3ac58955664922c4616289535d729a6d82f113c9de5d5f8d6a578a12
relaunched player's machine, contents rehashed:    0x45dfda061ef00a368c1950bbfdca9bd0b2c6a9c0270b63d0e16e3db3dec0cba1
VIOLATED: R4/O2: after a power loss the stored player must resume from a guaranteed directory and record the same root hash as an uninterrupted player (...)
run.sh: R1-O2-1: exit 1 (bug present)
```

The relaunched player passes all its own checks; its machine's contents hash to R, but it records R'. The reviewer
applied a tmp+sync+rename commit (clone into `machine.revert.tmp`, sync, remove the old backup, `rename_stored`) to a
scratch copy of `prt.lua` placed first on `LUA_PATH_5_4`; the modelled loss then hits `machine.revert.tmp`, the
relaunch falls back to the synced epoch machine, records R, and the test exits 0. Found, proved and reviewed on
Opus 5.5 (no fallback).

### Trigger and reachability

A host stop (power loss) of the player process after the clone into `machine.revert` and before its sync, at the end
of any input, followed by a relaunch on the same epoch directory. No adversary action is needed beyond inputs that
make the guest run (any input); the window opens once per input. The damaged state is the cached hash-tree data of
an unsynced clone, which O2 explicitly allows to be anything ("leaves every stored directory it was writing or
sharing in an unspecified state"); losing cached data while contents survive is a plausible outcome of unflushed
writeback across separate files. No unreachability argument is involved.

### Rating

1. Out of scope: not excluded. The closest exclusion is "Defects that need the honest operator to reload a stored
   directory that O2 does not guarantee, such as one being written or shared when its process stopped". Here the
   reload of the unguaranteed directory is not an external precondition imposed on the audited code: it is the
   audited component's own choice, and the defect is that choice. Section 5 binds it: "O1 and O2 bind the emulator
   too. The tools and reference implementations that ship with it must follow them", and "A defect that defeats the
   rebuild itself, or that damages a directory while O2 guarantees it, is not excused by them" (the player deletes
   the guaranteed epoch machine). The "Host faults" exclusion applies only "as long as the emulator does not turn
   them into a wrong hash"; the player does turn the stop into a wrong hash.
2. Role: Support (AUDIT.md table above). Section 3: "A defect that only a support component shows is Medium when it
   would rate High or Critical in the role the component stands in for, such as ... the honest operator for an
   implementation of an operator". The player is an implementation of an operator that no deployment runs; it
   stands in for the honest operator. "How to rate" step 2: "A defect that only a support component shows is never
   above Medium."
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." That
   requires the stood-in rating to be High or Critical, which step 4 gives.
4. Critical (in the stood-in honest-operator role): O2 "The operator discards those directories and resumes from a
   guaranteed one", and R4 "After a stop, it restarts from a directory that O2 guarantees and keeps defending its
   claim", violated on the honest operator's path ("Restarting after a stop (O2)", section 2); the result is a
   completeness failure ("The honest operator computes a wrong hash"). Critical for the honest operator, hence
   Medium for this support component.

Two readings: under the reading above (section 5 binds reference implementations to O2), Medium. Under a literal
reading of the out-of-scope entry ("need the honest operator to reload a stored directory that O2 does not
guarantee"), it would be Out of scope. The second reading would make O2 unenforceable on the very tools section 5
says must follow it, so the first is better supported. The deciding fact is whether the out-of-scope entry covers a
component under audit that itself performs the forbidden reload; the text of section 5 says it does not excuse it.

### Possible solution and risks

Make the backup refresh atomic, as other parts of `prt.lua` already do for checkpoints: clone into
`machine.revert.tmp`, `sync_stored` it, then remove the old `machine.revert` and `rename_stored` the temporary into
place (and sync the epoch directory). Add `machine.revert.tmp` (and the same for `pair`/`agreed` if they use the same
pair) to the names that `clear_epoch_directory` and `remove_epoch_leftovers` remove, so a leftover temporary does not
make reopening fail. Independently, `revert_interrupted_input` should prefer the epoch machine synced before
`state.json` was written when it matches, and the reopened epoch machine could be loaded with `clear_hash_tree` (at
the cost of a full rehash per reopen). Risks: a crash between removing the old backup and the rename leaves no
backup, so the reopen logic must handle the backup's absence (it already falls back to the epoch machine and
re-creates the backup); extra syncs cost I/O per input.

### Risk of not fixing it

The player and its stored mode are a reference implementation, not run by deployments; operators who copy its
crash-recovery design would, after a power loss at the end of an input, silently defend a wrong claim and lose
disputes. Anyone running the recipes for testing can get wrong root hashes after an unclean shutdown. Mitigation
outside the code: after any unclean stop, delete `machine.revert` before relaunching, or rebuild the epoch
directory from the template.
