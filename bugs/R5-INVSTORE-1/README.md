# R5-INVSTORE-1: `sync_stored` reports success after an earlier failed sync of the same directory

## What is asserted

A stored directory (operator's own clone of the bare-metal template, on XFS with `reflink=1`, a filesystem with reflinks as the manual requires) is loaded with
`SHARING_ALL`, 2048 RAM pages are changed, the root hash is recorded, the machine is destroyed and
`sync_stored` is called while the storage under the filesystem is full: it fails loudly with `ENOSPC` (a host fault,
allowed to stop the operator). The same process then frees the space and calls `sync_stored` again on the same directory (no stop in between;
the reviewer moved this retry into the same process, earlier it ran in a second process). The
directory now meets O2's definition (synced after the last change, machine destroyed without a crash before that
sync). The filesystem is remounted (page cache dropped, a reboot analog) and the directory is loaded without a
rebuild.

The test requires that either the second `sync_stored` fails, or the reloaded directory has the recorded root hash
(cached root and root rebuilt from the contents both equal it). A control directory, changed the same way and synced
while space is available in the same run, must reload with its root hash, otherwise the test exits 2.

Mechanism: `machine::sync_stored` (src/machine.cpp) reopens every file and fsyncs it (`os::sync_file`,
src/os-filesystem.cpp) and keeps no state. Linux reports a writeback error to one fsync and marks the failed pages
clean, so the second call finds nothing to write and succeeds although those pages (here of the RAM range's cached
hash-tree file `000000007ff00000-100000.dht`) never reached the disk.

## Requirement

- THREAT_MODEL section 4: "A host fault, such as a full disk or an output channel that refuses a write, may stop the
  honest operator, but the emulator must never turn one into a wrong hash, a wrong proof, or a directory that O2
  guarantees but that later loads as a different state."
- O2: "The emulator guarantees a stored directory only when it was synced after the last change to its contents and,
  if a machine used it with shared backing storage, that machine was destroyed without a crash before that sync."
- R9: "The content hash must equal the root of the actual contents. This applies to every cached, incremental, or
  persisted hash ... and every snapshot the emulator itself writes."
- src/cm.h, `cm_sync_stored`: "On success, all previous changes to the stored machine files are durable on disk."

## How to run

```sh
bugs/run.sh R5-INVSTORE-1
```

Needs root, tmpfs, a free loop device and `mkfs.xfs` (exit 2 otherwise). Uses the harness config
`baremetal-template`. Everything (a 330 MiB tmpfs, a 320 MiB XFS loop filesystem) lives in a `mktemp -d` directory
under /tmp and is unmounted and removed at exit. About 1 second.

Files: `test.sh` (mounts, fault injection, verdict), `phase.lua` (clone / dirty+sync(+retry) / check phases; the old
separate `sync` phase is no longer used by test.sh).

## Expected output on audit/prt2

```
first sync_stored (storage full):        FAILED: .../phase.lua:21: unable to sync file '.../000000007ff00000-100000.dht': fsync() failed: No space left on device
second sync_stored (space freed):        SUCCESS
control (synced without a fault):
expected (machine before destroy):  e15f3d65...
root after reload (cached tree):    e15f3d65...
test (sync failed, then succeeded):
expected (machine before destroy):  e15f3d658459f7775700fcfd97618de6c0a41464ac06e12dbc429a8e3749e36a
root after reload (cached tree):    9a790f637b582ca43ad1e120bf7062d6e99a89e46a0f674d96db0ef1be7d60bf
root rebuilt from the contents:     e15f3d658459f7775700fcfd97618de6c0a41464ac06e12dbc429a8e3749e36a
FAIL: sync_stored reported success, the directory meets O2, and it reloads as a different state (R9, section 4)
run.sh: R5-INVSTORE-1: exit 1 (bug present)
```

Exit 1 (reproduced on every run). Exit 0 once a sync after a failed sync of the directory fails, or the reload of the directory is refused
loudly while the control loads (phase status 4, added by the reviewer; earlier a refused load gave exit 2), or the
reload matches. On ext4 the same fault aborts the journal
and the second sync fails with EROFS, so the test uses XFS, a common filesystem with reflinks (the manual says only
"Stored machines need a filesystem with reflinks" and names none).
