# R1-O2-1: the PRT stored player restarts from its unsynced backup clone after a power loss

## Asserted

After a power loss right after an input is recorded, the relaunched stored player of `doc/recipes/prt.lua`
must record the same root hash as an uninterrupted player that ran the same inputs.

Requirements (THREAT_MODEL.md):

- O2: "A process that stops (crash, kill, or power loss) leaves every stored directory it was writing or sharing
  in an unspecified state. The operator discards those directories and resumes from a guaranteed one".
- R4: "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim."
- Section 5: "O1 and O2 bind the emulator too. The tools and reference implementations that ship with it must
  follow them".

## Mechanism

`run_next_input` records boundary N in `state.json` (the epoch machine is destroyed and synced first), and then
`stored_machine_pair_methods:commit` removes `machine.revert`, clones the epoch machine into `machine.revert` under
that final name, and only then syncs it. If the power fails before that sync, `machine.revert` exists but is not
guaranteed. On relaunch, `revert_interrupted_input` picks `machine.revert` because its contents, rehashed with
`clear_hash_tree`, match `state.json`. It then deletes the guaranteed epoch machine and replaces it with a clone of
the backup. `reopen_epoch_directory` loads that clone with `SHARING_ALL` and without `clear_hash_tree`, so the
player keeps using the backup's cached hash-tree data, which was never synced.

## Test

`test.lua` runs the stored player (prt.lua loaded unchanged as a module, driven by `player.lua`) in child
processes on the `baremetal-template` configuration (the emit-output bare-metal guest), using two inputs:

1. control: a fresh epoch directory gets inputs 0 and 1 with no stop. It records root hash R.
2. crash: a fresh epoch directory gets input 0. `player.lua crash` wraps the machine API's
   `clone_stored`/`sync_stored`. When the player is about to sync a clone of the epoch machine that it has not
   synced yet (its backup; cache entries are skipped), the wrapper models the power loss. One 4 KiB block of that
   clone's RAM `.dht` (the leaf hashes of RAM pages 0..127) reads back as zeros, like unflushed delayed-allocation
   data. The process then exits with `os.exit` and no cleanup. Directories that were already synced are left as
   they were.
3. relaunch: a new process opens the same epoch directory and is delivered inputs 0 and 1, as a restarted
   listener does. It records root hash R'.

The test asserts R' == R. It also prints the content hash of the relaunched player's machine, rehashed with
`clear_hash_tree`.

## Run

```sh
bugs/run.sh R1-O2-1
```

It takes about 10 s and writes about 100 MB to a `mktemp -d` directory, which it removes when it finishes.

## Expected on audit/prt2

```
uninterrupted player, root after input 1:          0x45dfda061ef00a368c1950bbfdca9bd0b2c6a9c0270b63d0e16e3db3dec0cba1
relaunched player, root it records after input 1:  0x2ff8357c3ac58955664922c4616289535d729a6d82f113c9de5d5f8d6a578a12
relaunched player's machine, contents rehashed:    0x45dfda061ef00a368c1950bbfdca9bd0b2c6a9c0270b63d0e16e3db3dec0cba1
VIOLATED: R4/O2: ...
run.sh: R1-O2-1: exit 1 (bug present)
```

The relaunched player passes every one of its own checks: the load assert, and `state.json` after input 1. It
silently records a root hash that is not the content hash of its machine.

To check that the test passes once the defect is fixed, apply the change to a scratch copy of `prt.lua`, not to
the tracked file. Make `commit` clone into `machine.revert.tmp`, sync it, then rename it to `machine.revert`, and
put the copy first on `LUA_PATH_5_4`. The modelled power loss then hits `machine.revert.tmp`. The relaunch falls
back to the synced epoch machine and records R, and the test exits 0. Loading the reopened machine with
`clear_hash_tree` should also make it pass.
