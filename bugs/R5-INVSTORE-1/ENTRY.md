## R5-INVSTORE-1

**Title.** After a `sync_stored` that failed on a host write error, a second `sync_stored` of the same directory reports success although the failed pages never reached the disk, and the directory then reloads with a wrong root hash

**Severity.** Critical (preferred reading: a host fault turned into a directory that O2 guarantees but that later loads as a different state). Low or Out of scope under the alternative reading that a failed `sync_stored` ends the directory's guarantee for good, so syncing it again is misuse.

### Problem

`machine::sync_stored` keeps no state. Each call reopens every stored file, calls `fsync` on the new descriptor,
closes it, and then syncs the directory entries. When writeback of a file fails, for example because the storage
under the filesystem is full or returns an I/O error, Linux reports the error once, to the first `fsync` that
checks it, and does not keep the failed pages dirty. The first `sync_stored` therefore fails loudly, as it should.
A later `sync_stored` of the same directory opens new descriptors, has nothing left to write for the failed pages,
and returns success, although those pages never reached the disk.

The documented contract says the opposite. `cm_sync_stored` (src/cm.h) states "On success, all previous changes to
the stored machine files are durable on disk". `cm_load` states "The directory holds a valid machine again only
after cm_destroy() succeeds and cm_sync_stored() then succeeds". The manual states "A directory used by a machine
with sharing holds a valid machine only after that machine was destroyed without a crash and the directory was
synced". After the second sync, the directory meets each of these conditions and O2's definition of a guaranteed
directory. Nothing in the API documentation, the manual or the threat model says that an earlier failed sync voids
a later successful one.

In the test, the lost pages belong to the RAM range's cached hash-tree file (`000000007ff00000-100000.dht`). After
a remount, which is a clean analog of the restart that O2 protects, loading the directory without a rebuild gives the
cached root `9a790f63...`. The machine that was destroyed had root `e15f3d65...`, and rebuilding from the contents
also gives `e15f3d65...`. The honest operator reloads its own directory without a rebuild, because O1 asks for a
rebuild only on adoption. Every claim it then computes from that machine starts from a wrong root hash. That is
the completeness failure of section 1: "The honest operator computes a wrong hash". If a content file loses its pages
instead, the reloaded contents themselves differ from the machine's.

### Component, role and area

Storing and syncing machines: `machine::sync_stored` and the file sync helpers it calls. AUDIT.md table, first row:
"Interpreter, ..., input delivery, and storing, loading, cloning and syncing machines | Honest operator".

### Location

- `src/machine.cpp`, `machine::sync_stored` (lines 712-721): calls `os::sync_file` on every stored file, then
  `os::sync_directory` on the directory and its parent. It records nothing about a failure.
- `src/os-filesystem.cpp`, `os::sync_file` (from line 726) opens a new read-only descriptor and calls `sync_fd`.
  `sync_fd` (lines 628-644) throws on an `fsync` error. That failure is not recorded anywhere and leaves no mark in
  the directory.
- `src/cm.h`, `cm_sync_stored` (lines 643-652) and `cm_load` (lines 573-575): the durability and validity promises
  quoted above. `doc/README.md`, the paragraph on `machine:sync_stored` (around line 5506) says the same.

### Evidence and test

`bugs/R5-INVSTORE-1/` contains `test.sh` (mounts, fault injection, verdict), `phase.lua` (clone, dirty and sync with
an in-process retry, and check phases, using the Lua API), and `README.md`. Run `bugs/run.sh R5-INVSTORE-1`. It
needs root, tmpfs, a free loop device and `mkfs.xfs`, and exits 2 without them. It uses the harness config
`baremetal-template`.

The test creates a 320 MiB XFS filesystem (`reflink=1`) on a loop device. The loop device is backed by a fully
allocated file in a 330 MiB tmpfs. The test clones and syncs the template twice: once as the test directory and once
as a control. It loads the control with `SHARING_ALL`, writes 2048 RAM pages, records the root hash, destroys the
machine, and syncs while space is available. Then it runs `fstrim`, which turns the free blocks into holes in the
backing file, and fills the tmpfs. The storage under the filesystem is now full, as on a full thin-provisioned disk.
The test does the same with the test directory: load with `SHARING_ALL`, write 2048 RAM pages, record the root,
destroy, and sync. The first `sync_stored` fails with `ENOSPC`. The same process then frees the space and calls
`sync_stored` again, with no stop in between. Finally the test remounts the filesystem and reloads both directories
without a rebuild. It also reloads each with `clear_hash_tree` to show the root of the contents.

On audit/prt2 it prints (temporary path shortened):

```
first sync_stored (storage full):        FAILED: .../phase.lua:21: unable to sync file '/tmp/r5-invstore-1.XXXXXX/mnt/machine/000000007ff00000-100000.dht': fsync() failed: No space left on device
second sync_stored (space freed):        SUCCESS
control (synced without a fault):
expected (machine before destroy):  e15f3d658459f7775700fcfd97618de6c0a41464ac06e12dbc429a8e3749e36a
root after reload (cached tree):    e15f3d658459f7775700fcfd97618de6c0a41464ac06e12dbc429a8e3749e36a
root rebuilt from the contents:     e15f3d658459f7775700fcfd97618de6c0a41464ac06e12dbc429a8e3749e36a
test (sync failed, then succeeded):
expected (machine before destroy):  e15f3d658459f7775700fcfd97618de6c0a41464ac06e12dbc429a8e3749e36a
root after reload (cached tree):    9a790f637b582ca43ad1e120bf7062d6e99a89e46a0f674d96db0ef1be7d60bf
root rebuilt from the contents:     e15f3d658459f7775700fcfd97618de6c0a41464ac06e12dbc429a8e3749e36a
FAIL: sync_stored reported success, the directory meets O2, and it reloads as a different state (R9, section 4)
run.sh: R5-INVSTORE-1: exit 1 (bug present)
```

It exits 1 on every run (the prover's 5 runs, and 7 by the reviewer). Each run takes about 1 second. The test exits
0 when any of these holds:

- the second `sync_stored` fails;
- the reload of the test directory is refused loudly while the control directory loads;
- the reload has the recorded root, both cached and rebuilt.

The test exits 2 if the first sync does not fail, which means the fault was not produced, or if the control directory
does not reload with its root.

The reviewer changed the test in two ways:

- The retry used to run in a second process. It now runs in the same process, so no stop happens between the failed
  sync and the successful one.
- A loud refusal to load the test directory used to give exit 2. It now counts as a pass (phase status 4).

On ext4 the same fault aborts the journal, and the second sync then fails with `EROFS`. The manual requires "a
filesystem with reflinks" for stored machines without naming one. XFS is a common choice. The defect was found,
proved and reviewed on Opus 5.5 without a fallback.

### Trigger and reachability

There is no adversary. The trigger is a host fault that makes file writeback fail at `fsync` time rather than at
write time. Examples are a thin-provisioned volume or pool that runs out of space under a filesystem that still has
free blocks, and a transient I/O error from the storage. The honest operator must then sync the same directory again
after the fault clears. This is a natural response to a transient fault, and nothing documents it as misuse. The
directory is the operator's own, written by documented operations: load with sharing, run or deliver, destroy, sync.
After the fault, the operator stores and reloads it on the honest operator's path, for example the epoch or revert
snapshot it resumes from after a restart. No guest or input is involved, so no reachability argument is needed.

### Rating

1. Out of scope: no. The host-fault exclusion holds only "as long as the emulator does not turn them into a wrong
   hash, a wrong proof, or a directory that O2 guarantees but that later loads as a different state (section 4)".
   Here the directory meets O2's definition ("The emulator guarantees a stored directory only when it was synced
   after the last change to its contents and, if a machine used it with shared backing storage, that machine was
   destroyed without a crash before that sync") and loads with a different root. The O2 reload exclusion ("a stored
   directory that O2 does not guarantee, such as one being written or shared when its process stopped, or one that a
   machine used with sharing after its last sync") does not apply. No process stopped, and the last sync came after
   the last use. The snapshot and O1 exclusions do not apply, because the operator's own process wrote the directory.
   Section 8, "How to rate", step 1: "A wrong hash after documented operations, destroying the machine, and a sync is
   not [out of scope]".
2. Role: honest operator. Section 3: "storing, loading, cloning and syncing machines (within the limits of O1 and
   O2) play this role in every deployment". The AUDIT.md table puts syncing machines in the honest-operator row.
3. High and Medium cases: none fits. The Medium persistence case needs "A persistence operation that fails loudly,
   without a wrong hash or damage to a directory that O2 guarantees". Here the second operation succeeds silently and
   the result is a wrong hash. The Medium case for "A machine API operation off the honest operator's path" does not
   fit, because syncing is on the path ("Storing and reloading the machine").
4. Critical, on the honest operator's path. Section 4: "A host fault, such as a full disk ..., may stop the honest
   operator, but the emulator must never turn one into a wrong hash, a wrong proof, or a directory that O2 guarantees
   but that later loads as a different state". R9: "The content hash must equal the root of the actual contents. This
   applies to every cached, incremental, or persisted hash, ... and every snapshot the emulator itself writes". R4:
   "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim". The documented
   promise of `cm_sync_stored` ("On success, all previous changes ... are durable on disk") is contradicted. Section 8
   says such a contradiction "takes the severity it would have if the manual were right".

Alternative reading: a failed `sync_stored` leaves the directory unspecified for good, so syncing it again and
relying on it is "a failure that needs misuse of an API by its trusted caller" (Low), or a reload of a directory that
O2 does not guarantee (Out of scope). Two facts decide between the readings:

- whether the model or the documentation makes a failed sync permanently disqualify a directory. Neither does. O2
  ties discarding to a process stop ("crash, kill, or power loss"), and R9 expects the process to keep going after
  failed updates.
- whether a production node plausibly retries a sync after a transient storage fault.

The preferred reading is Critical.

### Possible solution and risks

Make a sync failure sticky in the directory itself, so that it survives into later calls and other processes. When
`sync_stored` sees any `fsync` failure, it can invalidate the directory before it throws. For example, it can remove
or rename `config.json` and sync the parent, so that later syncs and loads fail loudly, or it can write a durable
"sync failed" marker that `sync_stored` and `load` refuse. The operator then has to fall back to its previous
guaranteed snapshot, which O2 already provides for. Retrying `fsync` inside the same call does not help, because the
error has already been consumed.

Risks:

- The invalidation can itself fail on a faulty disk. The call must then still fail, and the documentation must say
  that a directory whose sync failed must be discarded.
- Operators that currently retry would now see hard failures.
- The fix could optionally add a rebuild-and-compare on reload. That catches lost cached hash-tree pages but not lost
  content pages, so it is not a full fix.

### Risk of not fixing it

An honest operator whose storage hits a transient write failure, and that retries the sync after the fault clears,
holds a directory it is entitled to trust that, after a restart, gives a wrong root hash, or wrong contents. Its
claims from that point are wrong, and a dishonest claim can then win the epoch. Nobody can trigger the fault
deliberately without access to the operator's host, but thin-provisioned and network storage make it plausible.
Mitigations outside the code:

- treat any failed `sync_stored` as fatal and discard the directory;
- use storage that reports space exhaustion at write time;
- rebuild the hash tree on every reload (`--clear-hash-tree`) and compare it with the cached root. This covers only
  lost cached hash-tree pages.
