## R2-DFSTORED-1

**Title.** After an O1 adoption with `clear_hash_tree`, `store` with sharing `none` or `config` copies the template's
un-rebuilt `.dht`/`.dpt` files, so the operator's own synced snapshot reloads with the stale root hash.

**Severity.** Medium (preferred reading: storing with sharing `none` or `config` is a machine API operation off the
honest operator's path). Critical under the reading in which a production validator node stores an adopted template
with sharing `none` or `config` and later reloads that snapshot without a rebuild; see Rating.

### Problem

An operator adopts a stored machine it did not produce. As O1 requires, it loads it with `clear_hash_tree = true`.
The root hash `H` is then the content hash, and `verify_hash_tree()` succeeds. If the operator then calls
`machine:store(dir, SHARING_NONE)` or `machine:store(dir, SHARING_CONFIG)` and `sync_stored(dir)`, the new directory
holds the right contents. But for every range that is not shared, it also holds byte copies of the template's
original `.dht` and `.dpt` files. The rebuild never touched those files. Reloading this directory without a rebuild
gives the template's stale cached root instead of `H`, and `verify_hash_tree()` fails.

The directory was written by the emulator in the operator's own process, synced, and never used with sharing, so O2
guarantees it. R1 lets the honest operator reload such a directory without a rebuild. R9 requires every persisted hash
in every snapshot the emulator itself writes to equal the root of the actual contents. An operator that relied on
such a snapshot would compute a wrong hash and wrong claims from it, which is a completeness failure (section 1).
That outcome needs a node that stores with these modes. Otherwise the defect still violates R9.

`store` with sharing `all`, the default of the Lua binding and of the CLI, writes the in-memory trees and is correct.

### Component, role and area

Emulator core, storing machines: `machine::store`. In the AUDIT.md component table, "storing, loading, cloning and
syncing machines" has the role Honest operator. Area: how `store` persists the cached hash-tree data of ranges that it
copies from the initial backing stores, after `hash_tree::clear` rebuilt only the in-memory trees.

### Location

- `src/machine.cpp`, `machine::store`, unshared branch of the `store_address_range` lambda (about lines 460-480).
  `os::copy_file(c.data_filename, ...)` copies the initial data. When both tree files exist, it then runs
  `os::copy_file(c.dht_filename, dht_filename)` and `os::copy_file(c.dpt_filename, dpt_filename)` without checking
  that the trees still describe the data. In the same mode, the `.sht`/`.phtc` files are written blank.
- `src/hash-tree.cpp`, `hash_tree::clear` (line 744), called from `machine::clear_hash_tree` when the runtime config
  sets `clear_hash_tree`. It marks the in-memory dirty-page trees dirty and clears the in-memory dense trees. For an
  unshared load these are private mappings, so the files on disk keep the old data.
- `src/cm.h`, `cm_store` documents the modes: "CM_SHARING_NONE: Copies backing stores from the initial machine state
  (rarely useful). CM_SHARING_CONFIG: Store current machine state for shared backing stores; others are copied from
  the initial state."

### Evidence and test

`bugs/R2-DFSTORED-1/` contains `test.lua` (the test) and `README.md` (what it asserts and its expected output). Run it
with `bugs/run.sh R2-DFSTORED-1`. It takes about 8 s and uses about 300 MB in a `mktemp` directory under `/tmp`, which
it removes at exit.

The test copies `bugs/harness/work/configs/baremetal-template/machine` and fills its cache with a SHARING_ALL load,
`get_root_hash` and a sync. It then overwrites 64 bytes at offset 0x100000 of the RAM `.bin`, outside the emulator,
so the cached data describes other contents. The result models a foreign template whose contents are valid but whose
cache is stale. Cached data is not a valid-template condition.

The test records the stale cached root (plain load) and `H` (load with `clear_hash_tree`, which verifies). It exits 2
if they are equal. Then, for each mode `all`, `config` and `none`, it does the following:

1. Loads the template with `clear_hash_tree = true` and checks that the root is `H`.
2. Stores the machine with that mode and destroys it.
3. Runs `sync_stored` on the new directory.
4. Reloads the directory without a rebuild and records the root and the result of `verify_hash_tree()`.
5. As a precondition (exit 2 on failure), reloads it with a rebuild and checks that the contents give `H`.

The test asserts that, in every mode, the reloaded root equals `H` and the tree verifies.

On audit/prt2 it exits 1. The reviewer ran it twice and the prover three times, with the same output each time. The
`page ... is not marked dirty but is dirty` / `! FAILED!` lines that `verify_hash_tree` prints are left out here:

```
template stale cached root: 0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
template content hash (O1): 0xfda9eee87acd2a16b42a3c18191da8ece80e878b4fd228d3797954dc0b3dd27d
store sharing=all    reload root 0xfda9eee8...dd27d  (== content hash)  verify_hash_tree=true
store sharing=config reload root 0x428a6bb8...2ac75  (== STALE template cache)  verify_hash_tree=false
store sharing=none   reload root 0x428a6bb8...2ac75  (== STALE template cache)  verify_hash_tree=false
OK: R9/O1: after an O1 rebuild, store(dir, sharing=all) + sync_stored, ...
VIOLATED: R9/O1: after an O1 rebuild, store(dir, sharing=config) + sync_stored, ...
VIOLATED: R9/O1: after an O1 rebuild, store(dir, sharing=none) + sync_stored, ...
run.sh: R2-DFSTORED-1: exit 1 (bug present)
```

SHARING_ALL is the passing control. The rebuild precondition shows that only the cached data is wrong. The test exits
0 once `store` writes cached data that matches the stored contents. All agents ran on Opus 5.5 (`claude-opus-5-5`),
and no fallback was used.

### Trigger and reachability

The honest operator triggers it with documented operations alone. No adversary or guest action is needed beyond
supplying a template whose cached hash-tree data is stale. Anyone who distributes the template, or a damaged copy of
it, can supply one.

1. Adopt a valid template the operator did not produce with `clear_hash_tree` (O1).
2. Call `store(dir, SHARING_NONE)`, or `store(dir, SHARING_CONFIG)` with at least one range configured as not shared.
3. Run `sync_stored(dir)`.
4. Later, load `dir` without `clear_hash_tree`.

No state reachability is involved. The template satisfies every valid-template condition, and section 4 says "A
snapshot's cached hash-tree data is not part of any valid-template condition". The operator's own snapshots, written
from consistent trees, never trigger it.

### Rating

1. Out of scope: no.
   - "Defects that need the cached hash-tree data of a stored machine the operator did not produce to survive its
     adoption without a rebuild (O1)" does not apply. The operator did rebuild, and the emulator re-emitted the
     pre-rebuild files into a new snapshot. Section 5 says: "O1 and O2 bind the emulator too ... A defect that defeats
     the rebuild itself, or that damages a directory while O2 guarantees it, is not excused by them."
   - "Defects triggered only by loading a snapshot that the emulator did not write and that does not meet the
     conditions of a valid template" does not apply. The template meets them, and the reloaded directory is one the
     emulator wrote.
   - "Defects that need the honest operator to reload a stored directory that O2 does not guarantee" does not apply.
     The directory was stored, synced, and never used with sharing.
   - How to rate, step 1: "A wrong hash after documented operations, destroying the machine, and a sync is not" out
     of scope.
2. Role: `machine::store`. The AUDIT.md table gives "storing, loading, cloning and syncing machines" the role Honest
   operator. Section 3 says these "play this role in every deployment" "(within the limits of O1 and O2)", and the
   limits are respected here. That clause covers this component.
3. High and Medium cases: Medium fits under the preferred reading: "A machine API operation off the honest operator's
   path that, used as documented, leaves the hash tree, the cached state of the machine or a stored directory
   inconsistent with the machine's contents (R9)." This clause covers `store` with sharing `none` or `config` if that
   operation is off the honest operator's path. The manual calls `none` "rarely useful". Both modes store the initial
   state of unshared ranges instead of the current one. The Lua binding and the CLI default to `all`. The only
   operator implementation in this repository, the PRT player (Support), stores with the default `all`
   (`doc/recipes/prt.lua` line 2712). An operator that wants its own copy of an adopted template gets a correct one
   from `store(dir, SHARING_ALL)`.
4. Critical, under the alternative reading: "Storing and reloading the machine" is on the honest operator's path
   (section 2). If a production validator node stores an adopted template with sharing `none` or `config`, the
   defect violates R9 on that path: "The content hash must equal the root of the actual contents. This applies to
   every cached, incremental, or persisted hash, after any sequence of documented operations. It includes ... every
   snapshot the emulator itself writes", which means "a directory that O2 guarantees". The cached data is the kind R1
   lets the operator rely on: "it was either written by the operator's own process into a directory that O2
   guarantees, or rebuilt from the contents on adoption (O1). This rule applies to it". A reload without a rebuild
   would then give a wrong hash, a completeness failure, which section 8 rates "Critical" ("anywhere on the honest
   operator's path").

What decides between the readings: whether a production validator node (the Cartesi Rollups Node or the Dave sling
node, both outside this audit) calls `store` with sharing `none` or `config` on a machine adopted with
`clear_hash_tree`, and later reloads that snapshot without a rebuild. The threat model does not say whether a
documented but rarely useful mode of a component in the Honest operator role counts as "on the honest operator's
path".

### Possible solution and risks

In the unshared branch of `machine::store`, stop treating the source tree files as a trusted pair once the in-memory
trees were cleared. One fix records in the machine that it was loaded with `clear_hash_tree`, or that
`clear_hash_tree` was called since the load. For copied ranges, `store` then writes blank `.dht`/`.dpt` files with the
existing `os::truncate_file` path, so the next load rehashes those ranges. A simpler fix always writes blank trees for
copied ranges.

Risks:

- A load after a store with these modes rehashes the copied ranges. That cost is linear and bounded (R12), but slower
  than reusing trees.
- The in-memory trees must not be written instead of blank ones. With sharing `none` or `config` after the machine
  ran, the in-memory trees describe the current contents, not the copied initial ones.
- `clone_stored` has the same copying behavior. It is excused by O1, because loading a clone of a foreign directory is
  an adoption that must rebuild. The manual could say so explicitly.

### Risk of not fixing it

A node that adopts a template with `clear_hash_tree` and keeps its own copy through `store` with sharing `none` or
`config` would hold a synced, O2-guaranteed snapshot that reloads with the template's stale root. If it trusted that
root, it would defend wrong claims, and a dishonest claim could win. Anyone who distributes a template with stale
cached data, or a damaged copy of one, can trigger it.

Mitigations outside the code:

- Store adopted machines only with sharing `all`, which is the default.
- Alternatively, reload every snapshot derived from a foreign template with `clear_hash_tree`.
- Document in `cm_store` and the manual that `none` and `config` copy the source directory's cached hash-tree data
  unchanged.
