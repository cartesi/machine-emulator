## R1-O2-2

**Title.** After a stop just past the seal commit, reopening the sealed epoch swaps the synced epoch machine for an
unsynced clone and deletes `machine.revert`, so no O2-guaranteed copy is left and a later power loss blocks every
reopen.

**Severity.** Medium

### Problem

`seal_epoch_state` destroys and syncs the epoch machine, commits the sealed `state.json`, and only then removes
`machine.revert`. Suppose the player stops between those last two steps (crash, `kill -9` or power loss). On the
relaunch, `reopen_epoch_directory` calls `revert_interrupted_input`. `machine.revert` rehashes to the sealed root hash,
so branch 1 runs: it removes the synced `machine/`, then runs `clone_stored(machine.revert, machine)` and never calls
`sync_stored`. Next, the sealed-epoch path of `reopen_epoch_directory` removes `machine.revert` ("A sealed epoch no
longer needs the backup").

After that, the epoch directory holds no machine directory that O2 guarantees. `machine/` was changed and never synced,
and the synced backup is gone. On the next relaunch there is no backup, so `revert_interrupted_input` asserts that
`machine/` rehashes to `state.json`'s root hash. If a power loss has dropped the unsynced clone data, that assertion
fails with "the epoch machine does not match its state". Every later relaunch fails the same way. The player has no
fallback, such as clearing the epoch directory and replaying from the epoch checkpoint (`crisium.lua` `new_player`
calls `new_stored_player` directly). The honest player therefore stops defending the sealed epoch's claim, which in
the honest-operator role is a completeness failure (section 1).

### Component, role and area

The PRT stored player in `doc/recipes/prt.lua`, specifically its epoch directory and its restart path. AUDIT.md
assigns it this role: "The PRT player and bridge in `doc/recipes` ... Support. No production deployment runs the
player". It stands in for the honest operator's storing, reloading and restart after a stop.

### Location

- `doc/recipes/prt.lua`, `seal_epoch_state` (about lines 2720-2739): it commits `state.json` before removing
  `machine.revert`.
- `doc/recipes/prt.lua`, `revert_interrupted_input` (about lines 2864-2880): branch 1 runs `clone_stored` with no
  `sync_stored`, while branch 2 does sync its clone.
- `doc/recipes/prt.lua`, `reopen_epoch_directory` (about lines 3124-3127): it removes `machine.revert` for a sealed
  epoch without checking that `machine/` is synced.

### Evidence and test

`bugs/R1-O2-2/` contains three files:

- `test.lua`, the test.
- `player.lua`, the child process. It runs one player step per process: `seal-crash`, `reopen`, and the control's
  `reopen-synced-clone`.
- `README.md`.

Run it with `bugs/run.sh R1-O2-2`. It takes about 15-25 s and needs `strace` and the harness `baremetal-template`
configuration.

The test opens an epoch from `baremetal-template`, runs one input and seals. Through an `fs.exists` hook, the seal
process exits with `os.exit(17, false)` (no cleanup, the disk left as `kill -9` leaves it) right after the sealed
`state.json` commit and before `machine.revert` is removed. The test checks that `state.json` is sealed and that
`machine/` and `machine.revert/` both rehash to its root hash. It then relaunches under `strace -f -y` and makes two
checks:

- **(A)** Some machine directory must remain that matches `state.json` and was synced after its last change to file
  data and directory entries.
- **(B)** The test models a power loss: every file the relaunch changed and did not sync becomes a hole of the same
  size, which O2 allows because it leaves such files unspecified. The next relaunch must then reopen the sealed epoch.

A control in the same run applies the same steps to a relaunch whose `clone_stored` calls are each followed by
`sync_stored`. The control must pass both checks, or the test exits 2.

The reviewer re-ran the test twice on audit/prt2. It exited 1 both times. It prints:

```
control: after the relaunch, machine: matches state.json=true, files changed and not synced=0, entries synced=true
control: relaunch after the power loss: status 0
player: after the relaunch, machine: matches state.json=true, files changed and not synced=26, entries synced=false
player: after the relaunch, machine.revert does not exist
player: power loss discarded the data of 26 unsynced file(s)
player: reopen failed: .../doc/recipes/prt.lua:2874: the epoch machine does not match its state
control (reopen with synced clones): A and B hold
VIOLATED: O2/R4: after relaunching a sealed epoch, its directory keeps a machine directory at state.json's root hash that was synced after its last change
VIOLATED: O2/R4: after a power loss that follows that relaunch, the next relaunch reopens the sealed epoch
run.sh: R1-O2-2: exit 1 (bug present)
```

The power loss is modeled, not injected at the block layer, and the model is conservative: it keeps every directory
entry and drops only the data of unsynced files. Check (A) does not depend on the model. It applies O2's definition of a
guaranteed directory to the traced syscalls. The test ran on the temp directory's ext4, where `clone_file` copies. A
reflink clone also needs `sync_stored` to be durable (prt.lua's own comment on `get_stored_root_hash`). No reviewer
changes were made to the test. Opus 5.5 found, proved and reviewed the issue; no fallback model was used.

### Trigger and reachability

No adversary is needed. The trigger is two stops of the honest player's host:

1. A crash, kill or power loss inside the window of `seal_epoch_state` between the `state.json` write and the removal
   of `machine.revert`. That window covers `fs.sync_directory`, `remove_evicted` and the removal of the files the
   previous `state.json` named.
2. A power loss after the relaunch, before the kernel writes back the clone.

Both stops happen on the honest operator's path ("Restarting after a stop (O2)"). They work with any template and any
inputs, and the sealed epoch is reached on every epoch.

### Rating

1. **Out of scope: no.** I checked the exclusion "Defects that need the honest operator to reload a stored directory
   that O2 does not guarantee, such as one being written or shared when its process stopped". It does not apply. The
   first relaunch reloads `machine.revert`, which was synced. The defect is that the relaunch itself discards the only
   guaranteed copy. I also checked "Host faults, such as a full disk, as long as the emulator does not turn them into
   a wrong hash, ...". The second stop is a power loss, but O2 names power loss as an ordinary stop the operator
   resumes from: "A process that stops (crash, kill, or power loss) ... The operator discards those directories and
   resumes from a guaranteed one". Section 5 adds "The tools and reference implementations that ship with it must
   follow them". The trigger is the player's restart logic, not the fault.
2. **Role: Support.** The AUDIT.md table rows the PRT player as "Support. No production deployment runs the player".
   Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical in the role
   the component stands in for, such as ... the honest operator for an implementation of an operator". That clause
   covers this component, an implementation of an operator.
3. **High and Medium cases.** "A defect that only a support component shows, when section 3 rates it Medium." This
   case applies through step 4's rating in the stood-in role. No High case fits.
4. **Critical in the stood-in role.** In the honest-operator role, the defect violates two clauses on the honest
   operator's path. R4: "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim".
   O2: "The emulator guarantees a stored directory only when it was synced after the last change to its contents".
   Both would rate Critical, so the support rule gives **Medium**.

Alternative reading: if the host-fault exclusion were read to cover any power loss that ends in a loud failure, with
no wrong hash, the issue would be Out of scope. I judge that reading weaker. O2 and R4 make recovery from a power loss
an explicit requirement, and the fault here only exposes a guarantee the restart had already destroyed.

### Possible solution and risks

In `revert_interrupted_input` branch 1, call `cartesi.machine:sync_stored(machine_directory)` after `clone_stored`, as
branch 2 already does for its clone. The control in the test models exactly this fix. Another fix is to remove
`machine.revert` for a sealed epoch only after `machine/` is synced. The cost is one extra sync of a machine directory
per relaunch, a bounded per-restart cost. The fix touches only the restart path and does not change hashes.

### Risk of not fixing it

An operator that copies the reference player can lose the ability to restart a sealed epoch. That takes a stop inside
the seal window, then a power loss soon after the relaunch. It then stops defending that epoch's claim, and a
dishonest claim can win by timeout. No adversary can trigger it directly. As mitigations outside the code, an operator
can sync the filesystem after every relaunch, or recover by clearing the epoch directory and replaying the epoch from
its checkpoint.
