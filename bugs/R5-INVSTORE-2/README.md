# R5-INVSTORE-2: stored revert mode, crash-recovery rule resumes from a partially removed `machine.revert`

## What is asserted

`cartesi-machine --revert-mode=stored` is run as the manual shows it ("Rolling Cartesi Machines directly from
storage": `--load=machine,clone:<template>,sharing:all --cmio-advance-state=...`), on the harness bare-metal
template (`work/configs/baremetal-template`, guest `emit-output.c`) over two inputs. An `LD_PRELOAD` shim
(`killshim.c`) SIGKILLs the process, which stands in for a crash or power loss, inside the commit that follows the
accepted input 0. The kill comes right before the 3rd removal of a `machine.revert*` path, which today is inside
`remove_stored(machine.revert)`. At that point `machine` and `machine.revert.tmp` were already synced with the state
after input 0.

`recover.lua` then applies the documented recovery rule mechanically. The rule is in the CLI help for
`--revert-mode` and in doc/README.md: "If `machine.revert` exists, it holds that state, so discard `machine` and
`machine.revert.tmp` and clone `machine.revert` back to `machine`. If `machine.revert` is missing but
`machine.revert.tmp` exists, ... `machine` holds that state ...". The test requires that the directory the rule
resumes from can be cloned and loaded, that its cached root equals its rebuilt root, and that it holds a committed
state: the state after input 0 (or after input 1). The test computes both of those states independently from the
template. The test discards nothing, so the evidence stays on disk until the temp directory is removed.

The test is not tied to one fix. A fix that renames the backup away before removing it (checked with a patched
copy of the CLI that renames to `machine.revert.old`) or a corrected rule makes the test exit 0. The shim counts
removals under `machine.revert*` paths, except `machine.revert.tmp/`, where the clone's copy fallback unlinks the
files it has just created. It counts only once `input-0-outputs-merkle-root.bin` exists.

## Requirement (THREAT_MODEL.md)

- Section 5: "O1 and O2 bind the emulator too. The tools and reference implementations that ship with it must
  follow them, and the emulator must make them possible to follow."
- R4: "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim."
- Manual (doc/README.md): "`machine.revert` always holds a synced copy of the last committed state" and "After a
  crash or kill, the names left on disk tell where the last committed state is."

## Cause

`revert_stored.__index:commit` (src/cartesi-machine.lua) and `remove_backup` call `machine::remove_stored` on
`<dir>.revert`. That function (src/machine.cpp) unlinks the files one at a time, `config.json` last, and removes
the directory at the end. So the name `<dir>.revert` stays on disk while the directory is already incomplete. The
recovery rule checks `<dir>.revert` first.

## How to run

```sh
bugs/run.sh R5-INVSTORE-2        # about 30 s; needs gcc, the in-tree build and work/configs/baremetal-template
```

## Expected output on audit/prt2

```
killshim: SIGKILL before removing machine.revert/0000000000000000-8000.dpt
machine.revert holds 25 files, machine holds 27
  machine:            present, rebuilt root 1fd4a350... (after input 0)
  machine.revert:     present, does not load: unable to open backing file '.../machine.revert/0000000000000000-8000.bin' ...
  machine.revert.tmp: present, rebuilt root 1fd4a350... (after input 0)
rule: machine.revert exists -> discard machine and machine.revert.tmp, clone machine.revert to machine
VIOLATED: R4/O2: the documented rule resumes from machine.revert, which cannot be cloned: ... open() failed: No such file or directory; ...
run.sh: R5-INVSTORE-2: exit 1 (bug present)
```

Exit 0 means the rule recovers a committed state (fixed). Exit 2 is a setup error, for example when the shim did
not kill the CLI.
