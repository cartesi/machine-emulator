## R1-O1-1

**Title.** The documented O1 rebuild (`clear_hash_tree`) cannot adopt a valid template whose cached hash-tree files are malformed or missing: the loader parses and validates the cached data it is about to discard, and throws before the rebuild runs.

**Severity.** Critical

### Problem

O1 requires an operator that adopts a stored machine it did not produce to rebuild the cached hash-tree data from
the contents when it loads the machine. The manual names the mechanism: "Besides the machine state, the directory
holds cached hash-tree data, which is outside the state hash and is not checked on load. Load a directory you did not
produce with `--clear-hash-tree`, which rebuilds that data from the machine state, before trusting its state hash."
The same runtime option is `cartesi.machine(dir, {clear_hash_tree = true})`, `cm_load` and JSON-RPC `machine.load`.

`machine::machine` builds the address ranges and the hash tree from the cached files first. It validates their
structure and length, and only then calls `clear_hash_tree()`. So a directory whose hashed contents (every `.bin` and
`config.json`) are intact, but whose cached `hash_tree.sht`, `hash_tree.phtc`, `.dht` or `.dpt` files are malformed,
truncated or missing, fails to load with `clear_hash_tree`:

- `hash_tree::hash_tree` raises "inconsistent sparse hash tree nodes" for a bad sparse node index;
- `os::mapped_memory` requires the exact length of the `.sht`, `.dpt` and `.dht` files;
- the `page_hash_tree_cache` constructor raises "file tag mismatch";
- a missing `.dht` without sharing raises "unable to open backing file". The manual says instead that the emulator
  enables `mark_pages_dirty` "automatically when either tree backing file is omitted or missing", and
  `prepare_ar_backing_store` does set the flag, but the unshared mapping of the missing file still fails.

The cached data is exactly what the threat model treats as untrusted ("A snapshot's cached hash-tree data is not part
of any valid-template condition, so a snapshot the operator did not write is defended only after that data is
rebuilt (O1)"). A template whose cache was damaged in transit, relayed by another party or truncated is still a
valid template, but the honest operator cannot obtain it through the documented rebuild. It then cannot compute its
claim or respond, which is a completeness failure under section 1 ("cannot produce a proof that verifies, or cannot
respond in time. If the honest claim is eliminated, a dishonest claim can win").

**Second opinion.** The first reviewer refuted this candidate as Low. Its reasons were that every failure is a clean
exception, that the section 8 sentence "nothing it carries outside the hashed state may affect any transition (R1),
crash the honest operator, or corrupt its memory" lists no loud refusal, and that O1 is "possible to follow" because
a machine created from an edited `config.json` with blank cache filenames rebuilds to the same root. The second
opinion overturned that refusal on two steps that contradict the text:

1. The reviewer treated that out-of-scope sentence as the full list of what the emulator owes. "How to rate" step 4
   still applies: "violating any rule or obligation at a reachable state, or anywhere on the honest operator's path,
   is critical". The honest operator's path includes "Obtaining its valid template. For a template the operator did
   not produce, this includes rebuilding its cached hash-tree data (O1)". Section 8 also lists, as Medium, "A
   persistence operation that fails loudly ... in an uncommon host setup that the manual documents". That case would
   not be needed if a loud failure of a persistence operation were never a defect.
2. The workaround (edit `config.json`, clear the cache filenames, create a new machine from it) is not the rebuild
   the manual documents. Section 5 says "A defect that defeats the rebuild itself ... is not excused by them". The
   defect here defeats that rebuild itself.

### Component, role and area

Loading stored machines in the emulator core: the constructors of the address ranges, the hash tree and the page
hash-tree cache, run from `machine::machine`. AUDIT.md lists "storing, loading, cloning and syncing machines" as
Honest operator. The area is the O1 adoption of a template that the operator did not produce.

### Location

- `src/machine.cpp`, `machine::machine` (lines ~306-328). `m_ars` and `m_ht` are built from the cached files before
  `if (m_r.clear_hash_tree) clear_hash_tree();` at line ~326.
- `src/hash-tree.cpp`, `hash_tree::hash_tree`, line ~1001 ("inconsistent sparse hash tree nodes").
- `src/page-hash-tree-cache.hpp`, line ~443 ("corrupted page hash-tree cache: file tag mismatch").
- `src/os-mapped-memory.cpp`: exact-length checks (lines ~173, ~343, ~510) and "unable to open backing file".
- `src/memory-address-range.cpp`, `memory_address_range::memory_address_range` (the `m_dpt`/`m_dht` mappings);
  `src/machine-address-ranges.cpp`, `prepare_ar_backing_store` (lines ~158-187), which marks pages dirty for a
  missing tree file but creates the file only when the range is shared.
- Manual: `doc/README.md` lines ~1089-1094 (`--clear-hash-tree`) and ~3299-3306 (missing tree files).

### Evidence and test

`bugs/R1-O1-1/` contains `test.lua` and `README.md`. Run `bugs/run.sh R1-O1-1` (about 1 s). The test stores the
harness `baremetal-template` with sharing and records the content hash rebuilt from the untouched directory. It then
damages only cached hash-tree data on copies and requires that `cartesi.machine(dir, {clear_hash_tree = true})`,
with `SHARING_NONE` and with `SHARING_ALL`, succeeds with the reference root. Two controls (garbage hashes in the
`.sht` root and in the RAM `.dht`) must be rebuilt, or the test exits 2. On audit/prt2 the second-opinion re-run
printed:

```
reference root hash (rebuilt from contents): 0x428a6bb8...ac75
... 4 control lines: rebuilt, root matches
[SHARING_NONE] hash_tree.sht: left index of sparse node 2 changed: load with clear_hash_tree FAILS: ... inconsistent sparse hash tree nodes
[SHARING_ALL]  (same)
[*] hash_tree.sht truncated to 64 bytes: ... FAILS: ... length (64) does not match desired backing length (6144)
[*] hash_tree.phtc: unknown file tag: ... FAILS: corrupted page hash-tree cache: file tag mismatch
[*] RAM .dpt truncated to 10 bytes: ... FAILS: ... length (10) does not match desired backing length (32768) when initializing RAM
[SHARING_NONE] RAM .dht missing: ... FAILS: unable to open backing file '...dht': No such file or directory when initializing RAM
[SHARING_ALL]  RAM .dht missing: rebuilt, root matches
VIOLATED: ... 9 of 10 load(s) failed
run.sh: R1-O1-1: exit 1 (bug present)
```

All agents ran on Opus 5.5 (`claude-opus-5-5`): the hunter, the prover, the first reviewer and the second-opinion
reviewer. No fallback model was used.

### Trigger and reachability

The trigger is any party that distributes or relays the template directory, or any damage in transit, that leaves
the cached hash-tree files malformed, truncated or missing while the hashed contents stay intact. No guest action is
involved. The template is a valid template: every condition in section 2 concerns its contents and state, and
section 4 says its cached data "is not part of any valid-template condition". The honest operator meets the defect
on its own path when it adopts the template as O1 and the manual require.

### Rating

1. Out of scope: no. The snapshot exclusion needs "a snapshot that the emulator did not write and that does not meet
   the conditions of a valid template". This one meets them. The O1 exclusion covers "Defects that need the cached
   hash-tree data of a stored machine the operator did not produce to survive its adoption without a rebuild (O1)".
   Here the rebuild is requested and fails. Section 5 adds "A defect that defeats the rebuild itself ... is not
   excused by them". This is not misuse by a trusted caller either, because the caller uses the option the manual
   prescribes.
2. Role: loading stored machines is Honest operator (AUDIT.md: "... and storing, loading, cloning and syncing
   machines | Honest operator"). Section 3: these "play this role in every deployment".
3. High and Medium cases: none fits. "A persistence operation that fails loudly ... in an uncommon host setup that
   the manual documents, or while cleaning up after a stop" does not fit: the trigger is template data, not a host
   setup, and nothing is being cleaned up. "A crash, hang, memory-safety defect or unbounded allocation in a component
   in the honest-operator role, caused by data from other parties that the honest operator may decline" does not fit
   either. The failure is not a crash, and the operator cannot decline the template it defends.
4. Critical: the defect violates O1 as it binds the emulator ("O1 and O2 bind the emulator too. ... the emulator must
   make them possible to follow") on the honest operator's path ("Obtaining its valid template. For a template the
   operator did not produce, this includes rebuilding its cached hash-tree data (O1)"). It also violates R4 ("From
   any reachable state ... the honest operator can always compute the claim"). The valid template is a reachable
   state that the documented adoption cannot load. The manual contradiction about missing tree files ("enables it
   automatically when either tree backing file is omitted or missing") takes "the severity it would have if the
   manual were right", which is the same.

Alternative reading: Low. It holds if an undocumented workaround (creating a machine from an edited `config.json`)
counts as making O1 "possible to follow", and if a loud refusal of a valid template on the adoption path is not a
defect because section 8's snapshot sentence mentions only transitions, crashes and memory corruption. Two facts
would decide between the readings. The first is whether the maintainers intend `--clear-hash-tree` to be the single
documented O1 path, as the manual says. The second is whether section 2's "Obtaining its valid template" requires
that path to accept every directory with intact contents.

### Possible solution and risks

When `clear_hash_tree` is set, do not open or validate the cached tree files of the source directory. Instead,
create fresh in-memory (unshared) or freshly truncated (shared) tree storage for the `.sht`, `.phtc`, `.dht` and
`.dpt` files, sized from the configuration, and mark every page dirty. Equivalently, treat these files as absent
before the hash tree and address ranges are built. With sharing, the rebuilt files must replace the damaged ones in
the directory, and the replacement must keep the O2 rules (no partial file presented as guaranteed). Risks: a shared
load would rewrite the cache files of a directory that the caller may share with other processes. Sizing the fresh
`.phtc` must not come from an untrusted `phtc_size` (see R1-O1-2). Unshared loads also need anonymous storage for the
`.dht` and `.dpt` instead of mapping a missing file.

### Risk of not fixing it

An operator that receives a template with a damaged or tampered cache cannot adopt it with the documented command.
It has to obtain another copy, or edit `config.json` by hand, while its dispute clocks run. Anyone who relays
templates (a mirror, a package, a peer) can cause this refusal without touching the hashed contents, so the template
still matches the on-chain commitment and nothing points to tampering. Mitigation outside the code: on a copy, delete the
damaged per-range `.dht`/`.dpt` files and load with sharing (the shared path recreates missing per-range tree files;
the `.sht` and `.phtc` cases were not checked this way), or recreate the machine from its configuration with blank
cache filenames.
