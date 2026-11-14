# R5-INVSTORE-3: `cartesi-machine --store` never syncs the directory it writes

## What is asserted

The template that the manual builds with `cartesi-machine ... --store=<dir>` (doc/README.md, "Persistent Cartesi
Machines", and the template-creation commands that follow it) must be durable when the command returns, i.e. a
directory that O2 guarantees.

`store_machine` (src/cartesi-machine.lua ~3734) calls `machine:store` only, and the exit path calls `sync_stored`
only for `--load=...,sync` or `--revert-mode=stored`. `machine::store` writes with `ftruncate`/`pwrite` and never
calls `fsync`; src/cm.h says "The stored files are durable only after cm_sync_stored() succeeds".

* **Part A (deterministic, decides the verdict).** `strace -f -y` of
  `cartesi-machine --ram-image=accept.bin --ram-length=64Mi --no-root-flash-drive --max-mcycle=0 --final-hash --store=<dir>`.
  Requires every file of `<dir>`, `<dir>` itself and its parent to be `fsync`/`fdatasync`ed after creation (or a
  `sync`/`syncfs`), which is what `machine:sync_stored` and the CLI's own `--load=...,sync` key do. Positive
  control: the same parser on a trace of `--load=<c>,clone:<dir>,sharing:all,sync` finds 0 of 29 paths unsynced
  (otherwise exit 2).
* **Part B (power-loss simulation; root, tmpfs, loop devices).** The same command on an ext4 loop filesystem
  whose backing file is on tmpfs; the backing file is copied right after the command exits (what a power loss
  leaves), the copy is mounted, and `<dir>` must load with both the cached root and the root rebuilt with
  `clear_hash_tree` equal to the `--final-hash` value. Control: a directory stored the same way and then synced
  with `machine:sync_stored` must survive the same copy (otherwise exit 2). Skipped without root.

## Requirement

THREAT_MODEL.md section 5, O2: "The emulator guarantees a stored directory only when it was synced after the last
change to its contents". Section 5: "O1 and O2 bind the emulator too. The tools and reference implementations that
ship with it must follow them, and the emulator must make them possible to follow." Honest operator's path:
"Obtaining its valid template"; R4: "After a stop, it restarts from a directory that O2 guarantees". The CLI is a
Support component (AUDIT.md) standing in for the honest operator here.

## Run

```sh
bugs/run.sh R5-INVSTORE-3      # ~20 s; Part B needs root (loop + tmpfs mounts, cleaned up on exit)
```

## Expected output on audit/prt2

```
  subject: --store
  27 files in the stored directory; 29 of 29 required paths (files, directory, parent) never synced after creation
  Part A: VIOLATION, --store exits with its directory never synced
  ...
  subject (stored with --store only), expected 0x5567...06e6:
    directory present after the power loss: 27 files, 4 KiB on disk (before: 34760 KiB)
    cached root : load failed: [json.exception.parse_error.101] ... empty input ...
  Part B: VIOLATION, the template that --store reported as stored is lost by a power loss
BUG: 'cartesi-machine --store' returns before its directory is durable ...
run.sh: R5-INVSTORE-3: exit 1 (bug present)
```

In the copy the files exist with their sizes but no data (ext4 delayed allocation; the control's fsync committed
their metadata). The test then exits 1. With `machine:sync_stored(name)` added after `machine:store` in
`store_machine` (checked on a patched copy of the CLI), both parts pass and it exits 0.

Part B relies on the kernel not writing the subject's dirty pages back in the ~2 s between the store and the copy
(default `dirty_expire_centisecs` is 30 s); a global `sync` by another process at that moment would make Part B
pass, but Part A still decides exit 1.
