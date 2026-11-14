## R2-DFSTORED-2

**Title.** `clone_stored` hard-links a template's read-only files, so the documented clone-then-shared-load adoption, which the PRT stored player uses, refuses a valid template whose files are read-only (and one whose RAM backing file is trimmed).

**Severity.** Medium

### Problem

The PRT stored player adopts the application's template in `new_stored_player`. It calls
`cartesi.machine:clone_stored(template, epoch/machine)`, then loads the clone with `{ clear_hash_tree = true }` and
`SHARING_ALL`. The manual documents the same scheme. "Rolling Cartesi Machines directly from storage" loads "a fresh
clone of the rolling-calculator template" with `cartesi.SHARING_ALL`. `--load=<dir>,clone:<src>` switches the
default sharing to `all`, and the manual promises "Experiments run on the clone while the source directory stays
untouched."

`os::clone_file` hard-links every file that has no write permission bit ("Read-only backing files are hard-linked").
The shared-write mapping then refuses each such file ("is read-only and cannot be shared for writing", and for a
multiply-linked file "has multiple hard links"). So when a valid template's files are read-only, as a tar or OCI
layer, a package install or a protected store can leave them, the clone can never be loaded with sharing. The player
then cannot adopt the template and stops before it computes any claim. The same template loads unshared with
`clear_hash_tree` to the committed hash. File permission bits lie outside the hashed state and are not part of any
valid-template condition.

A second variant has the same effect. If the RAM backing file is trimmed after its last non-zero page, the contents
and the hash stay the same, and the unshared loader accepts the short file through `backing_gap`. `clone_stored`
keeps the short length, and the shared load refuses it ("does not match desired backing length"). The manual says,
however, that a mapped image's "size on disk must exactly match the length of the memory range", so this variant is
weaker (see Rating).

In the role the player stands in for, this is a completeness failure under section 1. The honest operator cannot
obtain its valid template, so it cannot respond, and a dishonest claim can win by default.

**Second opinion.** The first reviewer refuted this candidate as Low. Its reasons were that the manual documents both
refusals, that the template is left untouched, that the unshared `clear_hash_tree` load (O1) works, and that a
reported load error is not a "crash", so "no rule is violated". The second opinion overturned that refusal on the
following steps, which contradict the text:

1. The reviewer rated only the emulator's clone and load, in their Honest operator role, and never rated the
   component that shows the failure on an adoption path: the PRT stored player. "How to rate" step 2 says "Defects in
   the referee model, in guest software and in support components are rated as section 3 says". Section 3 rates a
   defect "that only a support component shows" as "Medium when it would rate High or Critical in the role the
   component stands in for, such as ... the honest operator for an implementation of an operator". A player that
   cannot obtain its valid template would violate R4 and the honest operator's path ("Obtaining its valid template")
   in the role it stands in for, which is Critical, so the support defect is Medium. Section 3 adds that "A defect is
   rated by the most critical role among the components that show it".
2. The reviewer read section 8's snapshot sentence ("affect any transition (R1), crash the honest operator, or
   corrupt its memory") as the full list of what is owed. Step 4 still covers "violating any rule or obligation ...
   anywhere on the honest operator's path", and section 8 lists a loud persistence failure as Medium only "in an
   uncommon host setup that the manual documents".
3. The manual documents hard-linking. It does not document that a clone of a read-only template cannot then be loaded
   with the sharing that `clone:` selects by default. Its promise that experiments run on the clone contradicts the
   behavior for variant A.

### Component, role and area

- The PRT stored player, `doc/recipes/prt.lua` `new_stored_player`. AUDIT.md: "The PRT player and bridge in
  `doc/recipes` ... | Support. No production deployment runs the player". It stands in for the honest operator's
  "Obtaining its valid template". This is the role the severity comes from.
- `machine::clone_stored`, `os::clone_file` and the shared-write checks of `os::mapped_memory`, in the emulator core.
  AUDIT.md: "storing, loading, cloning and syncing machines | Honest operator". The `cartesi-machine` CLI's
  `--load=<dir>,clone:<src>` (Support) shows the same failure.
- Area: adopting a template by clone plus shared load.

### Location

- `doc/recipes/prt.lua`, `new_stored_player` (lines ~3197-3219): `cartesi.machine:clone_stored(...)`, then
  `new_stored_machine(..., { clear_hash_tree = true })` with sharing.
- `src/os-filesystem.cpp`, `os::clone_file` (lines ~577-622): `read_only = (st.st_mode & S_WRITE_ALL) == 0` selects
  `hardlink_file`.
- `src/machine.cpp`, `machine::clone_stored` (lines ~526-576): clones every data, `.dht`, `.dpt`, `.sht`, `.phtc`
  and config file as is, at its length.
- `src/os-mapped-memory.cpp`: `check_shared_write_backing_file` (lines ~59-69) and the length check
  (`flags.shared || !flags.backing_gap`, lines ~164-175 and the corresponding checks of the other mappers).
- Manual: `doc/README.md` lines ~1147-1166 (`clone:`, default `sharing:all`), ~5498-5501 and ~5531-5533
  (`clone_stored` plus `SHARING_ALL` load of a template), and ~3285-3287 (exact image length).

### Evidence and test

`bugs/R2-DFSTORED-2/` contains `test.lua` and `README.md`. Run `bugs/run.sh R2-DFSTORED-2` (about 1 s, with a
temporary directory under `/tmp`). The test copies the harness `baremetal-template` and makes variant A (`chmod a-w`
on every file) and variant B (RAM `.bin` trimmed after its last non-zero page). For each, it checks the precondition
that the unshared `clear_hash_tree` load gives the reference hash (else exit 2). It then requires that
`clone_stored` followed by `load(clone, {clear_hash_tree=true}, SHARING_ALL)` succeeds with the reference hash, can
deliver an input and run, and leaves the template untouched. A control (the unmodified template) must pass. On
audit/prt2 the second-opinion re-run printed:

```
reference content hash: 0x428a6bb8...ac75
control: unmodified template
  clone_stored + SHARING_ALL load + run: OK, template untouched
A: template files read-only (chmod a-w, ...)
  unshared load with clear_hash_tree: hash equals reference
  clone_stored + SHARING_ALL load + run FAILED: ... backing file '.../clone2/0000000000000000-8000.bin' is read-only and cannot be shared for writing when initializing shadow state
  (info) unshared load + store(SHARING_ALL) + shared load instead: works
B: RAM backing file trimmed after its last non-zero page (same contents, same hash)
  clone_stored + SHARING_ALL load + run FAILED: ... length (2367488) does not match desired backing length (67108864) when initializing RAM
VIOLATED: section 8 / R4: ...
run.sh: R2-DFSTORED-2: exit 1 (bug present)
```

The test exits 1 if either variant fails. A fix limited to variant A therefore still leaves it at 1 until variant B
is fixed or the maintainers decide that B is not required and split the test (see Rating). All agents ran on Opus 5.5
(`claude-opus-5-5`): the hunter, the prover, the first reviewer and the second-opinion reviewer. No fallback model was
used.

### Trigger and reachability

No adversary is needed. The trigger is a valid template whose files lack write permission bits, as distribution and
packaging commonly leave them. An operator that adopts it through the documented clone-and-share scheme triggers the
failure, and the PRT stored player always does. For variant B, the trigger is anyone who trims a backing file of the
template without changing its contents. Guest state plays no part. The template meets every valid-template condition
in section 2, and the content hash recomputed from its contents matches.

### Rating

1. Out of scope: no. The snapshot exclusion needs a snapshot "that the emulator did not write and that does not meet
   the conditions of a valid template". Variant A was written by the emulator and only had its mode bits changed, and
   both variants meet the conditions. The O1 exclusion does not apply, because the load fails before the rebuild. O2
   does not apply, because there was no stop. A host fault is not involved either: read-only files are a normal
   distribution state, not a fault.
2. Role: the PRT stored player is Support, standing in for an implementation of the honest operator (AUDIT.md;
   section 3). The emulator's clone and load are Honest operator. Within that role, the documented O1 path (an
   unshared `clear_hash_tree` load followed by a store) still works, so the emulator's own share of the defect rates
   lower. Section 3: "A defect is rated by the most critical role among the components that show it".
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium". In the
   stood-in role, an operator that cannot obtain its valid template violates R4 ("the honest operator can always
   compute the claim") on the honest operator's path ("Obtaining its valid template"). That is Critical, so the
   support defect is Medium.
4. Critical: applies only under the alternative reading below.

Alternative readings. Critical, if a production node plausibly adopts templates by clone plus shared load, as the
manual's own "directly from storage" recipe does. Then the defect sits in the emulator's Honest operator role on the
honest operator's path (R4, "Obtaining its valid template"). Low, if the manual's "Read-only backing files are
hard-linked" is taken to document the refusal, and an operator is expected to make its template writable or adopt it
unshared. For variant B alone, Low or out of scope: the manual requires a mapped image's "size on disk [to] exactly
match the length of the memory range", so a trimmed file does not follow the documented format. Deciding facts: the
maintainers' intent for `clone:` and `clone_stored` on read-only sources, and whether production nodes adopt
templates this way.

### Possible solution and risks

In `clone_stored`, hard-link a read-only source only when the destination will stay read-only. Otherwise reflink or
copy it into a writable file of the full range length. Alternatively, give `clone_stored` a writable-clone mode and
use it in `clone:` and in the player. Pad a short backing file to the range length in the clone (sparse). In the
player, an independent fix is to adopt the template with an unshared `clear_hash_tree` load followed by
`store(dir, SHARING_ALL)`. Risks: copying instead of linking costs disk space and time for large read-only images
(the reason for the hard link). Silently making a hard-linked file writable would let a shared machine write through
to the template, which the shared-write check exists to prevent and which the test also guards against.

### Risk of not fixing it

An operator built like the PRT stored player cannot start defending an application whose template arrived with
read-only files. It needs manual intervention (chmod, or a different adoption path) while its clocks run. The failure
is loud, and no wrong hash results. Mitigation outside the code: make the template files writable by the operator
before cloning, or adopt the template unshared with `clear_hash_tree` and store it with sharing.
