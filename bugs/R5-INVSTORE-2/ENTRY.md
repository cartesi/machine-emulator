## R5-INVSTORE-2

**Title.** `cartesi-machine --revert-mode=stored` removes the old `<directory>.revert` in place, so a stop during a
commit leaves a partial `machine.revert`. The documented recovery rule then resumes from it and discards the two synced
copies of the committed state.

**Severity.** Medium (preferred). Low if the Medium case "while cleaning up after a stop" caps the stand-in rating.
Out of scope under a literal reading of the O2 reload exclusion.

### Problem

In stored revert mode, each commit (at the start, at the epoch's initial fixed point and after each accepted input)
does the following:

1. Destroys the machine and syncs `machine`.
2. Clones `machine` to `machine.revert.tmp` and syncs the clone.
3. Calls `remove_stored(machine.revert)`.
4. Renames `machine.revert.tmp` to `machine.revert`.

`machine::remove_stored` unlinks the files of `machine.revert` one at a time (`config.json` last) and removes the
directory only at the end. Until then the name `machine.revert` stays on disk over an incomplete directory. The clean
exit (`remove_backup`) removes `machine.revert` the same way.

The CLI help and the manual give a crash-recovery rule: "If `machine.revert` exists, it holds that state, so discard
`machine` and `machine.revert.tmp` and clone `machine.revert` back to `machine`." The manual also says that
"`machine.revert` always holds a synced copy of the last committed state". A stop inside step 3 makes both statements
false. After that stop:

- `machine` and `machine.revert.tmp` are synced and O2-guaranteed. Both hold the state after the committed input.
- `machine.revert` is missing files, so it cannot be cloned or loaded. O2 does not guarantee it, because the process
  was changing it when it stopped.

The documented rule picks the one directory O2 does not guarantee, and it tells the operator to discard the two that
O2 does guarantee. Section 5 says "O1 and O2 bind the emulator too. The tools and reference implementations that ship
with it must follow them". This tool's recovery procedure does not follow O2. An operator who follows it loses the
committed state and has to start over from the template, although the rule says starting over happens only when
neither name exists.

The failure is loud: the clone fails with `ENOENT`. No wrong hash results. The CLI is a support tool that computes
claims (outputs Merkle roots, computation hashes), so it stands in for the honest operator, whose restart obligation
(R4, O2) this breaks.

### Component, role and area

- **Component:** the `cartesi-machine` CLI (`src/cartesi-machine.lua`) in stored revert mode, together with the
  recovery rule documented in its `--revert-mode` help and in doc/README.md ("Rolling Cartesi Machines directly from
  storage").
- **Role:** Support. The AUDIT.md table says: "The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI,
  ... | Support. No production deployment runs the player, the bridge or the CLI."
- **Emulator API:** `machine::remove_stored` (honest-operator role) behaves as `cm.h` documents: "On failure, some
  files or the directory may remain. An interrupted removal can be completed by calling the function again". It is
  not the defect.
- **Same pattern in the manual:** the Lua excerpt in doc/README.md (`commit` calls
  `m:remove_stored(backup_directory)` and then renames) follows the same order.

### Location

- `src/cartesi-machine.lua`:
  - `revert_stored.__index:commit` (lines 3893-3918): `m:remove_stored(self.backup_directory)` comes before
    `try_rename_stored(m, temporary_directory, backup_directory)`.
  - `revert_stored.__index:remove_backup` (lines 3934-3939).
  - The `--revert-mode` help text (lines 163-175): "after a crash or kill, resume from <directory>.revert if it exists".
- `src/machine.cpp`: `machine::remove_stored` (lines 661-709), which unlinks files one by one in place and removes the
  directory last.
- doc/README.md, lines 2522-2541: the recovery rule. Lines 5535-5583: the Lua excerpt with the same commit order.

### Evidence and test

`bugs/R5-INVSTORE-2/` contains:

- `test.sh`: the driver.
- `killshim.c`: an `LD_PRELOAD` shim. It sends SIGKILL to the process right before its Nth `unlink`/`unlinkat`/`remove`/`rmdir`
  of a matching path.
- `recover.lua`: applies the documented rule and checks its result with the Lua API.
- `README.md`.

**How the test runs.**

1. `test.sh` builds the shim with gcc.
2. It runs the manual's command on the harness bare-metal template `work/configs/baremetal-template` (guest
   `emit-output.c`) with two inputs:
   `cartesi-machine --revert-mode=stored --load=machine,clone:<template>,sharing:all --cmio-advance-state=input_file_index_begin:0,input_file_index_end:2`.
3. The shim starts counting once `input-0-outputs-merkle-root.bin` exists. It counts removals of `machine.revert*`
   paths, except `machine.revert.tmp/`, and kills the CLI before the 3rd one. That point is inside
   `remove_stored(machine.revert)` during input 0's commit.
4. `recover.lua` computes the states after input 0 and after input 1 independently from the template. It reports
   what each directory left on disk rebuilds to (`clear_hash_tree`) and applies the rule. It clones instead of
   discarding, so the evidence stays on disk.
5. The test passes only if the directory the rule resumes from clones, loads, has a cached root equal to its rebuilt
   root, and holds one of the two committed states.

Run it with `bugs/run.sh R5-INVSTORE-2` (about 30 s). On audit/prt2 it prints the following. Paths are shortened, and
the reviewer saw the same output in two runs:

```
killshim: SIGKILL before removing machine.revert/0000000000000000-8000.dpt
machine.revert holds 25 files, machine holds 27
committed state after input 0: 1fd4a3507e3106e248c33ba04bbed6ef6037add0e41060e7563a2324c4ea1f91
committed state after input 1: c8bf66d5b3bc0d1b8e91077207756b61122b0cfb0c7180ade1387344eb9a4cbb
left on disk after the kill:
  machine:            present, rebuilt root 1fd4a350... (after input 0)
  machine.revert:     present, does not load: unable to open backing file '.../machine.revert/0000000000000000-8000.bin': No such file or directory when initializing shadow state
  machine.revert.tmp: present, rebuilt root 1fd4a350... (after input 0)
rule: machine.revert exists -> discard machine and machine.revert.tmp, clone machine.revert to machine
VIOLATED: R4/O2: the documented rule resumes from machine.revert, which cannot be cloned: unable to clone file from '.../machine.revert/0000000000000000-8000.bin' to '.../recovered/0000000000000000-8000.bin': open() failed: No such file or directory; the rule discards machine and machine.revert.tmp, the synced copies of the last committed state
run.sh: R5-INVSTORE-2: exit 1 (bug present)
```

The prover reported four runs that exited 1, and the reviewer re-ran the test twice with the same result. The
reviewer also checked a fix with a scratch copy of the CLI whose commit renames `machine.revert` to
`machine.revert.old` before removing it. With that copy, the same kill leaves `machine.revert` absent. The rule then
resumes from `machine`, which has cached root equal to rebuilt root, equal to the state after input 0, and the test
exits 0. The test was not modified. All agents ran on Opus 5.5 (no fallback).

### Trigger and reachability

The trigger is a stop of the operator's process (crash, kill, power loss) while a commit, or the clean exit, removes
`machine.revert`. O2 and R4 expect a stop to happen at any point ("A process that stops (crash, kill, or power loss)
...", "After a stop, it restarts").

No input or adversary is needed. Every stored-mode run goes through this removal:

- at the commit at the epoch's initial fixed point;
- after every accepted input;
- at the clean exit.

So the state is reachable with any valid template and any input sequence that has at least one commit after the
first. The window lasts for every unlink of the old backup, which on a large (Linux) machine covers dozens of files.

### Rating

1. **Out of scope.** The closest exclusion is "Defects that need the honest operator to reload a stored directory that
   O2 does not guarantee". `machine.revert` is such a directory. The defect, however, is not something that happens
   after an operator chooses on its own to reload it. The defect is that the shipped tool and its manual tell the
   operator to reload it and to discard the guaranteed directories. Section 5 rules that out: "O1 and O2 bind the
   emulator too. The tools and reference implementations that ship with it must follow them". So the defect is in
   scope. The host-fault exclusion does not apply: a kill is not a host fault, and the defect needs no fault of the
   host. Under a literal reading, where the O2 reload exclusion covers any defect whose trigger includes such a reload,
   the class would be Out of scope. The facts that decide are whether section 5's sentence about shipped tools
   overrides that exclusion when the tool itself directs the reload. This entry reads it as overriding.
2. **Role.** The component is the CLI and its documented rule, which is Support. Section 3 says: "A defect that only a
   support component shows is Medium when it would rate High or Critical in the role the component stands in for,
   such as ... the honest operator for an implementation of an operator or a tool that computes claims." The CLI
   computes claims (outputs Merkle roots, computation hashes), so it stands in for the honest operator.
   `remove_stored` in the emulator does what `cm.h` documents and does not show the defect itself.
3. **High and Medium cases.** The stand-in honest operator is rated here. The candidate case is "A persistence
   operation that fails loudly, without a wrong hash or damage to a directory that O2 guarantees, in an uncommon host
   setup that the manual documents, or while cleaning up after a stop." It does not fit, for three reasons:
   - the host setup is ordinary;
   - the operation that fails is the documented resume itself, not a cleanup;
   - the rule tells the operator to discard `machine` and `machine.revert.tmp`, which O2 guarantees, so the "without
     ... damage to a directory that O2 guarantees" condition fails.

   No High case fits.
4. **Critical (in the stand-in role).** "Restarting after a stop (O2)" is part of the "Honest operator's path". R4
   requires: "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim." O2 says:
   "The operator discards those directories and resumes from a guaranteed one". The documented rule resumes from the
   one directory O2 does not guarantee and discards the guaranteed ones. That violates R4 and O2 at a reachable state
   and on the honest operator's path, which is Critical in the honest-operator role. The support rule therefore makes
   it **Medium**, and step 2 caps a support-only defect at Medium.

**Second reading.** If the cleanup clause of the Medium case were read to cover a recovery procedure that fails loudly
after a stop, the stand-in rating would be Medium and the support defect would be Low. The facts that decide this are
two: whether resuming counts as "cleaning up after a stop", and whether discarding guaranteed directories on the
rule's instruction counts as "damage to a directory that O2 guarantees". This entry reads neither clause as met.

### Possible solution and risks

Make the old backup leave its name atomically before deleting it. In `commit` and `remove_backup`, call
`rename_stored(machine.revert, machine.revert.old)` (which is durable) and then
`remove_stored(machine.revert.old, REMOVE_FORCED)`. The rule must then also say that `machine.revert.old` is always
discarded. With this change, when `machine.revert` is absent and `machine.revert.tmp` is present, `machine` holds the
committed state, as the current rule already says.

Alternatively, keep the removal and correct the rule: resume from `machine.revert` only if it loads completely,
otherwise from `machine` when `machine.revert.tmp` exists. This is weaker, because "loads" is not proof of O2
guarantee. The same change belongs in the manual's Lua excerpt.

Risks of the fix:

- A leftover `machine.revert.old` from a previous crash would make the next rename fail. The first commit must refuse
  to start, or clean it up, just as it already refuses an existing `machine.revert` or `machine.revert.tmp`.
- With a remote server, all names refer to the server's filesystem, and the rename must stay on one filesystem.

### Risk of not fixing it

No production deployment runs the CLI, so the goal is not directly exposed. An operator or integrator who follows the
manual's recovery rule after a crash, kill or power loss during a commit or the clean exit would find that recovery
fails. If they follow the documented order, which discards first, they also delete the only intact copies of the
committed state and must re-run the epoch from the template. Node implementations that copy this documented pattern
inherit a restart that does not follow O2.

Mitigation until fixed: after a stop, do not trust `machine.revert` merely because it exists. If
`machine.revert.tmp` exists, resume from `machine`, which commit synced before cloning. Otherwise check that
`machine.revert` clones and loads completely before discarding anything.
