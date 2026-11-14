## R10-PERTEMPLATE-4

**Title.** Unknown members in an adopted template's unhashed `config.json` are read whole and parsed into a full JSON
document on every load and clone, so whoever ships the directory sets the memory the honest operator spends adopting
it, without bound (about 21 bytes of peak memory per byte of padding).

**Severity.** Critical (preferred reading). Low under the reading that "the bytes it covers" in R12 includes the
unhashed `config.json`, or that the whole template directory is trusted input (see Rating).

### Problem

`config.json` of a stored machine is outside the hashed state. `machine_config::load` reads the whole file with
`os::read_file`, parses it into a full `nlohmann::json` document, and then picks the fields it knows, silently
ignoring every other member. Nothing bounds the file's size or the number of unknown members. So a directory whose
hashed contents are exactly a valid template, and whose root hash after the O1 rebuild matches the on-chain
commitment, can carry an extra member such as `"x-padding": [0,0,0,...]`. The peak memory of loading it grows with
that padding, at about 21 bytes per byte, and not with the machine. A 64 MiB padding compresses (gzip) to about
65 KB, so the cost of shipping it is negligible.

`machine::clone_stored` parses the source `config.json` too, and then copies it byte for byte into the clone. The
PRT player makes its epoch machine, backups and cache entries with `clone_stored`, so every snapshot it keeps carries
the padding and every later load pays for it again. Only a load followed by `store` writes a normalized file.

A distributor or relay of a template can thus ship a directory that the honest operator cannot adopt on the host the
deployment was sized for. Under a memory limit, the load aborts the process (`std::bad_alloc` escapes and
`std::terminate` runs); without one, it consumes the host's memory. An operator that cannot obtain its valid
template cannot compute its claim or respond, which is a completeness failure under section 1 ("cannot produce a
proof that verifies, or cannot respond in time. If the honest claim is eliminated, a dishonest claim can win").

**Second opinion.** The first reviewer refuted this candidate as Low. Its reasons were that R12 requires loading to
be "at most linear in ... the bytes it covers", that a load covers the stored files it reads, `config.json` among
them, so a steady 21x per byte is linear, and that "No crash was shown, so 'crash the honest operator' (section 8)
is not met". The second opinion overturned that refusal on two steps that contradict the text:

1. Reading "the bytes it covers" as every byte of `config.json` makes the worst case of loading a fixed machine
   unbounded, which empties the word "bounded" in R12 ("has a worst case in host time and memory that is bounded and
   at most linear"). R12 measures each operation "from a machine at its starting position", and its bounds are what
   A7 sizes ("The total cost of an epoch is the application's mcycle usage times these bounds"). No deployment can
   size for a quantity that a template's distributor picks freely outside the machine. The campaign's confirmed
   R1-O1-2, where the unhashed `hash_tree.phtc_size` in the same file sets the adoption memory, was rated Critical
   on this same reading.
2. Section 8 says of a snapshot that meets the valid-template conditions that "nothing it carries outside the hashed
   state may ... crash the honest operator". That forbids the possibility, not one observed crash. The reviewer's own
   measurement shows the memory grows linearly with an unbounded, unhashed quantity, so a crash follows on any finite
   host. The second opinion also ran it (below): with 128 MiB of padding under a 2 GiB address-space limit, which the
   control adopts at 139 MB, the adoption aborts with `std::bad_alloc`.

### Component, role and area

Emulator core: loading and cloning stored machines (`machine_config::load`, `machine::clone_stored`). AUDIT.md
component table: "Interpreter, state-access layers, devices, uarch program, hash tree, log producers, ..., input
delivery, and storing, loading, cloning and syncing machines | Honest operator". The area is the O1 adoption of a
template that the operator did not produce, and every later load of its clones. The PRT player (Support) multiplies
the cost through `clone_stored`.

### Location

- `src/machine-config.cpp`, `machine_config::load` (lines ~125-151): `os::read_file(name)` of the whole file, then
  `nlohmann::json::parse(data)`, then `ju_get_field(j, "config", c, "")`, which ignores unknown members. No size
  limit.
- `src/machine.cpp`, `machine::clone_stored` (lines ~526-578): `machine_config::load(from_dir)` parses the source,
  then `os::clone_file` copies `config.json` byte for byte.
- `src/machine.cpp`, `machine::machine`: every load, `clear_hash_tree` included, goes through
  `machine_config::load`.

### Evidence and test

`bugs/R10-PERTEMPLATE-4/` contains `test.lua` (the test), `child.lua` (adopts, clones or re-stores one directory in
a child process and reports its root hash, peak RSS `VmHWM` and CPU time), and `README.md`. Run it with
`bugs/run.sh R10-PERTEMPLATE-4` (about 20 s). `R10PT4_PAD_MIB=<n>` changes the large padding, which defaults to
64 MiB.

The test copies the harness's stored `baremetal-template` machine (64 MiB RAM, 75.8 MiB of address ranges, waiting
at a manual yield with the accepted reason, root in `root-hash.txt`) as the control. It makes copies that differ only
by an unknown top-level member in `config.json` of 16 MiB and 64 MiB. It adopts each as O1 requires, by loading
without sharing with `clear_hash_tree = true` and calling `get_root_hash()`. It requires the root hash to be the
control's, and the peak memory to be no larger than the larger of 2x the control's and the control's plus twice the
bytes of the machine's address ranges, a bound that depends only on the machine. The second-opinion re-run on
audit/prt2 printed:

```
machine covers 75.8 MiB in its address ranges; control config.json 3780 bytes
control:            VmHWM=  139512 kB cpu=0.11 s root=428a6bb8...ac75
padded config.json of 67112660 bytes compresses (gzip) to 66282 bytes
padded config.json   16781012 bytes: VmHWM=  383668 kB cpu=1.09 s root=428a6bb8...ac75 (2.75x control)
padded config.json   67112660 bytes: VmHWM= 1415864 kB cpu=4.24 s root=428a6bb8...ac75 (10.15x control)
marginal peak memory: 21.00 bytes per byte of unhashed padding (small->big)
clone_stored: VmHWM=1415776 kB; clone's config.json 67112660 bytes (source 67112660 bytes)
load+store normalizes it: stored config.json 3780 bytes
allowed peak: 294736 kB (max of 2.0x control, control + 2 x 75.8 MiB of address ranges)
VIOLATED: R12 ... observed 1415864 kB, 10.15x the control's 139512 kB
run.sh: R10-PERTEMPLATE-4: exit 1 (bug present)
```

A second-opinion check, not part of the test: `child.lua adopt` under `prlimit --as=2GiB`. The control adopts
normally (139 MB). The same contents with a 128 MiB padding print `terminate called after throwing an instance of
'std::bad_alloc'` and abort.

All agents ran on Opus 5.5 (`claude-opus-5-5`): the hunter, the prover, the first reviewer and the second-opinion
reviewer. No fallback model was used.

### Trigger and reachability

The trigger is whoever produces, distributes or relays the template directory the honest operator adopts: they add
unknown members to `config.json`. The honest operator triggers the cost on its own path by following O1, loading the
directory with `clear_hash_tree` to rebuild the cached data and compare the root hash with the on-chain commitment.
Every load and every `clone_stored` reads the file. The hashed contents are a valid template; the root is the
committed one, and the test checks it against `root-hash.txt`. No guest action and no unreachable state is involved.

### Rating

1. Out of scope: not excluded. The snapshot exclusion covers "Defects triggered only by loading a snapshot that the
   emulator did not write and that does not meet the conditions of a valid template (section 4)". Every condition
   in section 2 concerns the machine's contents and state, and these meet them. The same entry continues: "Once a
   snapshot meets them, nothing it carries outside the hashed state may affect any transition (R1), crash the honest
   operator, or corrupt its memory." That covers unhashed padding. The O1 exclusion ("Defects that need the cached
   hash-tree data of a stored machine the operator did not produce to survive its adoption without a rebuild")
   does not apply: the operator rebuilds, and the padding is not cached hash-tree data. The host-fault exclusion
   does not apply: the trigger is the directory's contents, not a fault of the host.
2. Role: Honest operator. Section 3: "storing, loading, cloning and syncing machines (within the limits of O1 and
   O2) play this role in every deployment". The AUDIT.md row quoted above lists loading and cloning machines as
   Honest operator, and that row covers `machine_config::load` and `machine::clone_stored`. The defect is on the
   honest operator's path, section 2: "Obtaining its valid template. For a template the operator did not produce,
   this includes rebuilding its cached hash-tree data (O1)."
3. High and Medium cases: none fits. The constant-factor case needs "the guest, or host load that the deployment
   was sized for" as the trigger; here it is the directory's distributor, and the factor is not constant relative to
   the machine. The same entry says "When the sizing is unknown, rate ... a super-linear or unbounded one Critical."
   "A crash, hang, memory-safety defect or unbounded allocation in a component in the honest-operator role, caused
   by data from other parties that the honest operator may decline" does not fit under the preferred reading: the
   operator cannot decline the template it defends, which it needs "to compute its own claim" (section 4). No
   Medium case concerns loading on the operator's path.
4. Critical: violated on the honest operator's path. Section 8, Out of scope (snapshots): "nothing it carries outside
   the hashed state may ... crash the honest operator". R12: "storing, loading, cloning or syncing a machine" has a
   worst case "bounded and at most linear in the cycles it executes or the bytes it covers"; here the cost is set by
   unhashed bytes, not by the machine. R4/section 1: an operator that cannot adopt its valid template "cannot
   respond in time". Section 8: "violating any rule or obligation ... anywhere on the honest operator's path, is
   critical".

Second reading, Low: "the bytes it covers" in R12 includes every byte of the stored `config.json`, so 21 bytes per
byte is linear and R12 holds; and section 4's "Snapshots are trusted input" with "the valid template it chose to
defend" on the trusted side makes a padded `config.json` a trusted party's choice ("a failure that needs misuse of
an API by its trusted caller"). An intermediate reading gives High if a template from another party is data the
operator "may decline". Two facts would decide. First, whether R12's "bytes it covers" for loading means the
machine's state or every byte of the directory; the first reading keeps "bounded" meaningful and matches the
confirmed R1-O1-2. Second, whether the section 8 sentence on what a snapshot "carries outside the hashed state"
covers unknown members of `config.json`.

### Possible solution and risks

Bound the cost of `config.json` by the machine, not by the file. Either parse with a streaming or SAX parser that
reads only the known fields and skips unknown members in bounded memory, or keep the DOM parser but refuse a file
larger than a fixed bound well above any configuration the emulator writes. Under the campaign's reading, a refusal
of a directory whose contents are a valid template is itself a loud refusal on the operator's path, so the skipping
parser is preferable. In `clone_stored`, write the configuration normalized (`to_c.store(...)`) instead of cloning
the source file, so that padding never propagates.

Risks: a size bound must stay above the largest legitimate configuration (many flash drives, long bootargs and
paths). Normalizing in `clone_stored` changes the clone's `config.json` bytes; tools that compare clones byte for
byte must follow. Rejecting unknown members outright could break directories written by a newer emulator that adds
fields.

### Risk of not fixing it

Anyone who distributes or relays a template (an application's published snapshot, a mirror, a peer) can make every
honest operator that adopts it as O1 prescribes abort or exhaust its host's memory, while the directory's root hash
still matches the on-chain commitment and nothing points to tampering. Every clone the PRT player keeps inherits the
padding. Mitigation outside the code: check the size of `config.json` before loading, or load once and `store` to
normalize it under a memory limit, or build the template from its configuration.
