# R1-O2-2: reopening a sealed epoch leaves no guaranteed epoch machine

Component: PRT stored player, epoch directory (`doc/recipes/prt.lua`: `seal_epoch_state`,
`revert_interrupted_input`, `reopen_epoch_directory`). Role: Support (the PRT player), standing in for the honest
operator.

## What happens

`seal_epoch_state` destroys and syncs the epoch machine, commits the sealed `state.json`, and only then removes
`machine.revert`. If the player stops between those last two steps, the relaunch runs `revert_interrupted_input`.
`machine.revert` matches the sealed root hash, so the function removes the synced epoch machine and replaces it with
`clone_stored(machine.revert, machine)`, which it never syncs. `reopen_epoch_directory` then removes
`machine.revert` for the sealed epoch, and that removal is durable. After this the epoch directory holds no stored
machine that O2 guarantees. The next relaunch needs one, because with no backup `revert_interrupted_input` asserts
that `machine` rehashes to `state.json`'s root hash.

## Requirement

THREAT_MODEL.md, O2: "The operator discards those directories and resumes from a guaranteed one". "The emulator
guarantees a stored directory only when it was synced after the last change to its contents". Section 5: "The tools
and reference implementations that ship with it must follow them". R4: "After a stop, it restarts from a directory
that O2 guarantees and keeps defending its claim".

## What the test asserts

`test.lua` runs every player step in its own process, as `prt-supervise.sh` relaunches do. `player.lua` holds the
child steps.

1. `seal-crash`: opens an epoch from the harness `baremetal-template`, runs one input and seals. The process exits
   without cleanup (`os.exit(17, false)`, the disk left as `kill -9` leaves it) at the moment `seal_epoch_state` has
   committed the sealed `state.json` and is about to remove `machine.revert`. The test checks that `state.json` is
   sealed and that `machine` and `machine.revert` both rehash to its root hash.
2. `reopen` under `strace -f -y`: the relaunch. The trace records every change to file data and directory entries,
   and every `fsync`.
3. **(A)** After the relaunch, the epoch directory must still hold a machine directory (`machine` or
   `machine.revert`) that rehashes to `state.json`'s root hash and was synced after the last change to its files and
   entries.
4. **(B)** A power loss is simulated next. Every file of those directories that the relaunch changed and did not
   sync loses its data: it becomes a hole of the same size, which O2 allows because it leaves such files
   unspecified. The old inode is unlinked, so no hard-linked file is written. The next relaunch must then reopen the
   sealed epoch.

Control, in the same run: the same steps with a relaunch whose `clone_stored` calls are each followed by
`sync_stored`, a stand-in for a fix. The control must pass A and B. If it does not, the test exits 2 (harness
error). Keeping `machine.revert` until the clone is synced would also pass: A through `machine.revert`, and B
through branch 1 of `revert_interrupted_input`.

## Run

```sh
bugs/run.sh R1-O2-2      # about 25 s; needs strace and the harness baremetal-template configuration
```

Exit status: 1 when the bug is present, 0 when fixed, 2 on a harness error.

## Expected output on audit/prt2

```
control: after the relaunch, machine: matches state.json=true, files changed and not synced=0, entries synced=true
control: relaunch after the power loss: status 0
player: after the relaunch, machine: matches state.json=true, files changed and not synced=26, entries synced=false
player: after the relaunch, machine.revert does not exist
player: power loss discarded the data of 26 unsynced file(s)
player: reopen failed: .../doc/recipes/prt.lua:2874: the epoch machine does not match its state
VIOLATED: O2/R4: after relaunching a sealed epoch, its directory keeps a machine directory at state.json's root hash that was synced after its last change
VIOLATED: O2/R4: after a power loss that follows that relaunch, the next relaunch reopens the sealed epoch
run.sh: R1-O2-2: exit 1 (bug present)
```

Notes. The test runs on the temp directory's filesystem (ext4 here, where `FICLONE` fails and `clone_file` falls
back to a copy). A and B do not depend on that: A uses O2's definition of a guaranteed directory, not filesystem
behavior. The power loss is modeled, not injected at the block layer. It is conservative: it drops only the data of
unsynced files and keeps every directory entry.
