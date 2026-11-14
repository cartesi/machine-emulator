## R3-VARCACHE-1

**Title.** `replace_memory_range` on a machine loaded with sharing swaps the range only in memory, so after destroy and `sync_stored` the O2-guaranteed directory reloads to a spliced state (post-run registers, pre-replacement memory) that no execution reaches.

**Severity.** Medium (preferred reading: `replace_memory_range` is off the honest operator's path). Critical under the reading that a production validator node replaces memory ranges of a machine that shares its stored directory (see Rating).

### Problem

`machine::replace_memory_range` swaps a memory range's backing store in the live machine (`m_ars.replace`, and the
current configuration `m_c`, which only a later `store` reads). It neither refuses a machine whose ranges are mapped
shared onto a stored directory D (loaded with `SHARING_ALL`, or `SHARING_CONFIG` for a shared range), nor records the
replacement in D (D's `config.json` and D's backing file of that range are left untouched). Every other range of the
machine, the registers included, stays mapped onto D's files and keeps changing them.

So after the documented sequence load D with sharing, replace `.ram`, deliver an input, run to the yield, destroy
the machine without a crash, and `sync_stored(D)`, D is a directory that O2 guarantees ("synced after the last change
to its contents and, if a machine used it with shared backing storage, that machine was destroyed without a crash
before that sync"). It reloads to a state that differs from the one the machine had when it was destroyed: the
registers, mcycle and rx/tx buffers after the run, but the RAM contents from before the replacement. The reload
passes an O1 rebuild and `verify_hash_tree`, because D's cached hash-tree data is consistent with D's spliced contents;
nothing detects that the directory does not hold the machine.

This contradicts the manual. For the CLI it says "Mode `all` keeps every backing store up to date with changes made
while the machine runs. When `cartesi-machine` exits cleanly, the directory already holds the machine as it was left,
ready to be loaded again", and for the API "A directory used by a machine with sharing holds a valid machine only after
that machine was destroyed without a crash and the directory was synced". `cm.h` documents only "A later cm_store()
uses the new backing store" for the replacement, and nothing forbids replacing a range of a shared machine. The CLI
refuses `--replace-memory-range` only together with `--revert-mode=stored` (`src/cartesi-machine.lua:2955`); it accepts
it with `--load=D,sharing:all,sync` and `--revert-mode=none`.

It violates R9 ("This applies to every cached, incremental, or persisted hash, after any sequence of documented
operations. It includes ... every snapshot the emulator itself writes", where the latter "means a directory that O2
guarantees") and section 4's requirement that the emulator never produce "a directory that O2 guarantees but that
later loads as a different state". It does not threaten the goal of section 1 while no node on the honest operator's
path replaces memory ranges of a machine that shares its directory (see Rating).

### Component, role and area

- `machine::replace_memory_range` (and `machine_address_ranges::replace`): the rest of the machine API (C `cm_replace_memory_range`, Lua `machine:replace_memory_range`, JSON-RPC `machine.replace_memory_range`). AUDIT.md role: "Honest operator where a production validator node plausibly calls it on the honest operator's path. When unsure, give both ratings."
- Loading with sharing, destroying and `sync_stored`: "storing, loading, cloning and syncing machines", role Honest operator; they behave as designed on their own and show the defect only after the replacement.
- The `cartesi-machine` CLI (`--load=...,sharing:all,sync` with `--replace-memory-range`): Support; it reaches the defect through the API.

Area: persistence of a machine that shares its stored directory.

### Location

- `src/machine.cpp`, `machine::replace_memory_range` (around lines 723-764): no check of the machine's sharing of D; updates only `m_ars` and `m_c`.
- `src/machine-address-ranges.cpp`, `machine_address_ranges::replace` (around lines 662-686): builds a new `memory_address_range` from the replacement backing store, dropping the mapping onto D's file.
- `src/machine.cpp`, `machine::sync_stored` (around line 712): syncs D's files as listed by D's own `config.json`; nothing records that one range now lives elsewhere.
- `src/cm.h`, `cm_load` and `cm_replace_memory_range` documentation; `doc/README.md`, the `sharing:<mode>` paragraph of the CLI section and the `sync_stored` paragraph of the stored-machines section.
- `src/cartesi-machine.lua:2945-2956` (CLI accepts the combination with `--revert-mode=none`), `3268-3271` (calls `replace_memory_range` after `load`).

### Evidence and test

`bugs/R3-VARCACHE-1/` contains `test.lua` (the test) and `README.md`. The test uses the harness configuration
`baremetal-template` (a valid template built by `bugs/harness/configs/make-configs.sh`, a bare-metal guest waiting at
its first accepted manual yield) and needs nothing else; it works in a temporary directory that it removes.

For each of two scenarios it clones the template to a temporary D, syncs it, loads it with `cartesi.SHARING_ALL` and
`clear_hash_tree = true`, delivers one advance input (`payload = "hello"`), runs to the next manual yield, records the
root hash, destroys the machine, runs `sync_stored(D)` and reloads D with `clear_hash_tree = true` (O1 rebuild). The
control does no replacement and must round-trip (else exit 2). The test scenario first replaces `.ram` with an image
that differs from D's RAM file in one byte at `0x83000000` (48 MiB into RAM, a byte the guest never touches). Exit 0 if
`replace_memory_range` or `sync_stored` refuses, or if D reloads to the machine's final root hash; exit 1 if it reloads
to another root hash.

Run: `bugs/run.sh R3-VARCACHE-1` (about 7 s). On audit/prt2 it exits 1 on every run (reviewer: 2 runs; prover: 3
runs) and prints:

```
control (no replacement): final 0x0ccbd06ae4441af3e34307d7951666d81bfb54b00f8dd54bb8d8fc5312880b5d mcycle 8588695
control reloaded:         root  0x0ccbd06ae4441af3e34307d7951666d81bfb54b00f8dd54bb8d8fc5312880b5d mcycle 8588695
template root:            0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
after replace .ram:       0xa1cc5cd82204856e49d35eb12d4b4952e77ae076b3e908e445a7927fb7a99751
machine after input:      0x0c035851e11785d4379b2c3309561753e607efe2cbed21cfbfb81cd8dbed97fb mcycle 8588695, RAM byte at probe 0x5a
D reloaded (O1 rebuild):  0xe07b2ec9e31508be9d2a40b730dc009815a2cb48494a796fd17656e12348918e mcycle 8588695, RAM byte at probe 0x00
D's reloaded root equals: none of the machine's root hashes
VIOLATED: a directory shared by a machine, destroyed without a crash and synced (O2-guaranteed) must reload to the machine's state (R2, R9, section 8 step 1)
run.sh: R3-VARCACHE-1: exit 1 (bug present)
```

The reloaded D has the machine's final mcycle but the pre-replacement RAM byte: a state the machine never had.

Reviewer checks outside the test (not part of `bugs/R3-VARCACHE-1/`): reloading the same D without
`clear_hash_tree` gives the same `0xe07b...` root and `verify_hash_tree()` returns true, so D's cached hash-tree data is
consistent with D's spliced contents and nothing flags the directory. The CLI reproduces it too:
`cartesi-machine --revert-mode=none --load="D,clone:<baremetal-template>/machine,sharing:all,sync"
--replace-memory-range="label:.ram,data_filename:img" --final-hash` prints final hash `0xa1cc5cd8...b7a99751`, exits
cleanly and syncs, and D then reloads (O1 rebuild) to the template root `0x428a6bb8...ec92ac75`, contradicting the
manual's "the directory already holds the machine as it was left".

Found, proved and reviewed by Opus 5.5 (no fallback).

### Trigger and reachability

The trusted caller of the machine API (or the `cartesi-machine` CLI) loads a stored directory with `SHARING_ALL` (or
`SHARING_CONFIG` with the range shared), replaces a memory range, uses the machine, destroys it and syncs the
directory. No input sender, guest or claimant can trigger it: it needs the caller to call `replace_memory_range`.

Reachability on the honest operator's path: the honest operator's path (section 2) is obtaining the valid template,
observing the chain, advancing, delivering inputs, storing and reloading, computing claims, producing proofs,
submitting transactions and restarting. None of these replaces a memory range, and a valid template is a machine
"created from a configuration ... and changed only by running it and delivering inputs", so a machine whose range was
replaced after creation is not one the honest operator defends. The PRT player and the referee model in `doc/recipes`
never call `replace_memory_range` (only the `run-calculator-with-new-drives.lua` example does, on a machine loaded
without sharing). The state is not a guest-reachable state at all: it is created by the replacement plus the
persistence path, whatever the inputs.

### Rating

1. Out of scope: no. The trigger is documented operations followed by destroying the machine and a sync. Step 1 says
   "A wrong hash after documented operations, destroying the machine, and a sync is not" out of scope. The directory is
   one O2 guarantees ("synced after the last change to its contents and, if a machine used it with shared backing
   storage, that machine was destroyed without a crash before that sync"), so the exclusion for "a stored directory
   that O2 does not guarantee, such as one being written or shared when its process stopped, or one that a machine used
   with sharing after its last sync" does not apply. The exclusion "The effect of a deliberate state change made through
   the machine API, when the API performs it as documented" covers the new RAM contents of the live machine, which the
   API does produce; it does not cover the directory losing that change while keeping the later register changes,
   which the manual contradicts ("the directory already holds the machine as it was left"). It needs no snapshot the
   emulator did not write and no skipped O1 rebuild.
2. Role: the component that shows the defect is `replace_memory_range`, "The rest of the machine API (C, Lua and
   JSON-RPC)", whose role is "Honest operator where a production validator node plausibly calls it on the honest
   operator's path. When unsure, give both ratings." (AUDIT.md). A production PRT validator node does not plausibly call
   it on the honest operator's path (see Trigger and reachability), so the preferred role is a machine API operation
   off that path; the Critical reading below treats it as on the path. The CLI (Support) also shows it, but only
   through the API.
3. High and Medium cases: Medium, "A machine API operation off the honest operator's path that, used as documented,
   leaves the hash tree, the cached state of the machine or a stored directory inconsistent with the machine's contents
   (R9)." This clause covers the component: `replace_memory_range` is a machine API operation, used as documented (no
   document forbids it on a shared machine, and the CLI accepts the combination), and it leaves the stored directory D
   inconsistent with the machine's contents at destroy (RAM byte `0x00` in D against `0x5a` in the machine; root
   `0xe07b...` against `0x0c03...`). The manual contradiction rates the same: "It takes the severity it would have if the
   manual were right."
4. Critical: does not apply under the preferred reading, since step 3 matched. Under the alternative reading, in which
   a production node replaces a memory range of a machine that shares its directory on the honest operator's path
   ("Storing and reloading the machine. Reloading means loading a directory that O2 guarantees"), it violates R2
   ("Every way of copying, persisting, restoring, or sharing a machine" must agree on the canonical hash), R9 and
   section 4 ("a directory that O2 guarantees but that later loads as a different state") on that path, which is
   Critical: a node restarting from D (R4, "After a stop, it restarts from a directory that O2 guarantees") would compute
   wrong hashes.

Two readings: Medium if no production node calls `replace_memory_range` on a shared machine on the honest operator's
path (the facts above: the valid-template definition excludes post-creation replacement, and the shipped PRT player
does not do it); Critical if some deployment's node does. A Low reading ("a failure that needs misuse of an API by its
trusted caller") is not supported: nothing in `cm.h`, the manual or the API marks the combination as misuse, the API
does not refuse it, and the CLI deliberately allows it except with `--revert-mode=stored`.

### Possible solution and risks

Simplest: make `replace_memory_range` refuse a range that is mapped shared onto a stored directory the machine was
loaded from (or refuse any replacement on a machine loaded with `SHARING_ALL`/`SHARING_CONFIG` for a shared range), and
have the CLI reject `--replace-memory-range` with any `sharing` mode other than `none`, as it already does with
`--revert-mode=stored`. Alternatively, record the replacement in D: copy the new contents into D's backing file of the
range and keep it mapped shared (so D stays self-contained), which makes the replacement cost linear in the range size
and must itself be atomic with respect to O2 (a crash partway leaves D unguaranteed, which O2 already allows while the
machine is live). Rewriting D's `config.json` to point at the external file would make D depend on a file outside it
and break `clone_stored`/`remove_stored`, so it is not recommended. Risks: refusing breaks callers that today replace
ranges of shared machines and never reload the directory (for example a CLI run with `sharing:all` and an NVRAM
replacement); document the restriction in `cm.h` and the manual.

### Risk of not fixing it

A caller or operator that combines sharing with a range replacement (for example instantiating a template's drives on
a `clone:`-loaded directory with the CLI, whose `clone:` defaults to `sharing:all`) gets a synced directory that loads
silently to a state no execution reaches, with a consistent hash tree, and may later defend, store or publish it as
the machine it ran. No adversary can trigger it; it takes the trusted caller's own sequence of calls. Mitigation
outside the code: do not call `replace_memory_range` on a machine loaded with sharing; load with `SHARING_NONE`,
replace, run, and `store` to a new directory instead.
