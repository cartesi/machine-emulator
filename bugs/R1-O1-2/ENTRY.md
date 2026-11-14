## R1-O1-2

**Title.** The unhashed `hash_tree.phtc_size` in a template's `config.json` survives the O1 rebuild, so whoever ships
the directory sets the memory the honest operator spends adopting it, without bound.

**Severity.** Critical (preferred reading). Low under the reading that the whole template directory, unhashed
configuration included, is trusted input (see Rating).

### Problem

The capacity of the page hash-tree cache, `hash_tree.phtc_size`, is read from the stored `config.json` of a machine
directory. It is not part of the hashed state: it does not change the root hash. Loading with
`clear_hash_tree = true`, the rebuild that O1 requires before an operator trusts the root hash of a template it did
not produce, clears the cache's contents but keeps its capacity. No runtime option can override the capacity. The
cache maps `phtc_size` entries of about 12 KiB each, and both its initialization and `clear()` write every entry.
The peak memory of adopting a template therefore grows linearly with a number that the template's distributor
chooses freely, independent of the machine's size. A sparse `hash_tree.phtc` of the matching length costs the
distributor no disk.

A distributor can thus ship a directory whose hashed contents form a valid template, and whose root hash after the
rebuild matches the on-chain commitment, but which the honest operator cannot adopt on the host the deployment was
sized for. The load either fails with an error, as when a memory budget makes the mapping fail, or is killed when
it exhausts the host's memory. An operator that cannot obtain its valid template cannot defend the honest claim.
That is a completeness failure (section 1). The inflated value is also copied into every directory the operator
later stores or clones from that machine.

### Component, role and area

Emulator core: loading stored machines. AUDIT.md component table: "Interpreter, state-access layers, devices, uarch
program, hash tree, log producers, ..., input delivery, and storing, loading, cloning and syncing machines |
Honest operator". The area is the hash tree's page hash-tree cache, sized from the loaded configuration.

### Location

- `src/machine-config.cpp`, `machine_config::load` and `adjust_ht_backing_store_config`: the stored `hash_tree`
  configuration, `phtc_size` included, is taken from `config.json`. Only the filenames and the sharing mode are
  adjusted. `src/json-util.cpp:1784` reads `phtc_size` with no bound.
- `src/hash-tree.cpp:979` (`hash_tree::hash_tree`): builds `m_page_cache` with `config.phtc_size`.
- `src/page-hash-tree-cache.hpp:413-453` (constructor): maps `get_storage_length(num_entries)`, calls
  `m_map.reserve(num_entries)`, and initializes every entry and payload of an uninitialized file. The checks at
  461-472 refuse only zero and `ptrdiff_t` overflow. `clear()` at 597-604 writes every payload.
- `src/machine.cpp:326` (`machine::machine`): `clear_hash_tree` runs `clear_hash_tree()` on the cache as sized.
  Nothing resets or bounds the capacity.
- `src/machine.cpp:504-516, 566`: `store` and `clone_stored` write or clone a phtc of the same capacity.
- `src/machine-runtime-config.hpp`: no runtime field sets the cache capacity.

### Evidence and test

`bugs/R1-O1-2/` contains `test.lua` (the test), `child.lua` (adopts one directory in a child process and reports its
root hash, peak RSS `VmHWM`, CPU time and loaded `phtc_size`), and `README.md`. Run it with
`bugs/run.sh R1-O1-2`. `R1O12_BIG=<n>` changes the large capacity, which defaults to 65536.

The test copies the harness's stored `baremetal-template` machine as the control. That machine has 64 MiB of RAM,
waits at a manual yield with the accepted reason, was stored with the default `phtc_size` 4096, and covers 19403
pages. The test then makes copies that differ only in `config.json` `hash_tree.phtc_size` (16384 and 65536), each
with an empty sparse `hash_tree.phtc` of the exact length. The length formula is checked against the file the
emulator wrote. Each copy is adopted as O1 requires, by loading without sharing with `clear_hash_tree = true` and
then calling `get_root_hash()`. The test requires the root hash to be unchanged. It also requires the peak memory to
be no larger than the larger of 2x the control's and the control's plus a cache covering every page of the machine.
Output on audit/prt2, the same on two reviewer runs apart from a few kB:

```
machine covers 19403 pages (75.8 MiB)
control: phtc_size=4096   VmHWM= 139732 kB cpu=0.28 s root=428a6bb8...ac75
crafted: phtc_size=16384  VmHWM= 287940 kB cpu=0.35 s root=428a6bb8...ac75  (2.06x control memory)
crafted: phtc_size=65536  VmHWM= 880080 kB cpu=0.77 s root=428a6bb8...ac75  (6.30x control memory)
marginal cost: 12.0 kB of peak resident memory per phtc entry (MID->BIG)
phtc_size survives clear_hash_tree: stored 65536 entries -> loaded 65536
allowed peak: 372568 kB (max of 2.0x control, control + 19403 pages x 12 KiB)
VIOLATED: R12 ... must cost at most 372568 kB of peak memory (bounded by the machine's size); observed 880080 kB, 6.30x the control's 139732 kB
run.sh: R1-O1-2: exit 1 (bug present)
```

Reviewer repair: the prover's limit was 2x the control alone. A fix that clamps the capacity to the machine's own
page count, about 323 MB here, would still have failed it. The limit now also allows the control plus 12 KiB per
page of the machine. The test still exits 1, with a 2.4x margin.

Two more reviewer checks, not part of the test:

- A machine created from a configuration with `hash_tree.phtc_size = 65536`, from the same template's config, is
  accepted. Its `store()` writes `"phtc_size":65536` and an 807 MB `hash_tree.phtc`. So a directory that the
  emulator itself writes, for a machine created from a configuration with no check disabled, carries the value.
- In a child under `prlimit --as=2GiB`, the control adopts normally (139 MB). The same contents with
  `phtc_size = 262144` fail to load, with `unable to map backing file '.../hash_tree.phtc' to memory: Cannot
  allocate memory`.

The trend is linear at about 12 kB per entry. By extrapolation, not run, about 2^20 entries (12 GB) exhaust this
16 GB host. Found, proved and reviewed on Opus 5.5. No fallback was used.

### Trigger and reachability

The trigger is whoever produces or relays the template directory the honest operator adopts. They set
`hash_tree.phtc_size` in `config.json`, either at creation or by editing it, and ship a `hash_tree.phtc` of the
matching length, which may be sparse. The honest operator triggers the cost on its own path by following O1: it
loads the directory with `clear_hash_tree` to rebuild the cached data and compare the root hash with the on-chain
commitment. Every load path reads the value. The hashed contents are a valid template. The root hash is the
committed one, and the test checks this against the stored `root-hash.txt`. No unreachable state is involved.

### Rating

1. Out of scope: not excluded. The snapshot exclusion covers "Defects triggered only by loading a snapshot that the
   emulator did not write and that does not meet the conditions of a valid template (section 4)". The contents here
   meet every condition: "created from a configuration, without disabling any of the emulator's consistency
   checks", and with the committed content hash "after rebuilding its cached hash-tree data (O1)". An
   emulator-written directory with the same value exists (above). The same entry continues: "Once a snapshot meets
   them, nothing it carries outside the hashed state may affect any transition (R1), crash the honest operator, or
   corrupt its memory." That covers this case. The O1 exclusion ("Defects that need the cached hash-tree data of a
   stored machine the operator did not produce to survive its adoption without a rebuild (O1)") does not apply. The
   operator performs the rebuild, and the capacity survives it. Section 5 adds: "A defect that defeats the rebuild
   itself ... is not excused by them."
2. Role: Honest operator. Section 3: "storing, loading, cloning and syncing machines (within the limits of O1 and O2)
   play this role in every deployment". The AUDIT.md row quoted above lists loading machines as Honest operator.
   The clause covers this component directly. The defect is on the honest operator's path, section 2: "Obtaining its
   valid template. For a template the operator did not produce, this includes rebuilding its cached hash-tree data
   (O1)."
3. High and Medium cases: none fits. The constant-factor case is "A defect that lets the guest, or host load that
   the deployment was sized for, multiply the worst-case cost of an operation listed in R12 by a constant factor".
   Here the trigger is neither the guest nor host load. The factor is not constant either: the distributor picks it
   freely, and the same entry says "When the sizing is unknown, rate ... a super-linear or unbounded one Critical."
   The cost does not arise only from unreachable states. No Medium case concerns loading on the operator's path.
4. Critical: violated on the honest operator's path. Section 8, Out of scope (snapshots): "nothing it carries outside
   the hashed state may ... crash the honest operator". The adoption fails, or exhausts the host's memory, from an
   unhashed value. R12: "storing, loading, cloning or syncing a machine" has a worst case "bounded and at most
   linear in the cycles it executes or the bytes it covers". The cost is set by `phtc_size`, not by the machine's
   contents. R4/section 1: an operator that cannot adopt its valid template "cannot respond in time". Section 8:
   "violating any rule or obligation ... anywhere on the honest operator's path, is critical."

Second reading, Low: section 4 lists "the valid template it chose to defend" as trusted and says "Snapshots are
trusted input". `phtc_size` is a documented configuration field (manual, "Fields `hash_tree.phtc_size` ... control
the *page hash-tree cache*"), plain in `config.json`. On that reading, choosing or accepting a huge value is a
trusted party's configuration choice that the deployment sizes for: "a failure that needs misuse of an API by its
trusted caller" (Low). Two facts would decide, and the text points to the first reading. First, whether the
section 8 sentence about what a snapshot "carries outside the hashed state" covers unhashed configuration values as
well as cached hashes. Second, whether "the bytes it covers" in R12 means the machine's state, or also the logical
length of a stored cache file. Taken literally, the second meaning would make even a sparse file count.

### Possible solution and risks

Do not take the cache capacity from the stored directory when it is adopted. Under `clear_hash_tree`, the file is
being rebuilt anyway. Either reset the capacity to the default or to a new runtime option, recreating
`hash_tree.phtc` at that length, or clamp it to the number of pages that the machine's address ranges cover.
Optionally also refuse, at creation and on load, a `phtc_size` above that page count.

Risks: the phtc file layout depends on the capacity, so a shared load must resize or recreate the file before
mapping it. Directories stored afterwards get a different `hash_tree.phtc` length, and tools that check that length
must follow. Operators that deliberately use a large cache for speed would need the runtime option. The root hash
must stay unaffected, because the cache is only a cache. The test checks this.

### Risk of not fixing it

Anyone who distributes or relays a template, for example an application's published snapshot or a mirror of it, can
make every honest operator that adopts it as O1 prescribes fail to load it. They can also make the load consume all
of the host's memory, while the directory's root hash still matches the on-chain commitment. The emulator offers no
documented setting against this. An operator can mitigate it outside the code. It can inspect `config.json` and
reset `hash_tree.phtc_size`, recreating `hash_tree.phtc` at the matching length, before loading. It can also build
the template itself from its configuration, or load under a memory limit and treat a failure as a sabotaged
directory.
