# R5-INVPLAYER-1: a one-time fault while building a uarch claim makes the PRT player refuse that claim for good

**Component.** `doc/recipes/prt.lua`, `event_handler.commit_uarch_claim` and `try_new_uarch_tree` (the
`util.protect` wrapper and `self.failed_uarch_periods`). `doc/recipes/prt-bridge.lua` `build_claim` calls it again
on every tick while the inner tournament can still be joined. The PRT player is Support (AUDIT.md) and stands in for
the honest operator.

**What the test does.** It opens a stored player, as crisium runs it, on the harness `baremetal-template`
(the `emit-output` guest at its first accepted yield), delivers one input and seals the epoch. Then it calls
`commit_uarch_claim(player, 0, 0)` once while the soft `RLIMIT_NOFILE` is lowered to the number of descriptors
already open. This causes a real, transient host fault: cloning the entry into `pair/` fails with
`open() failed: Too many open files`. Next the test restores the limit and calls `commit_uarch_claim` three more
times, as the bridge would on later ticks. As a control, it builds the same claim directly with
`player:new_uarch_tree(0, 0)`, which succeeds once the fault has cleared.

**What it asserts.** Once the fault is gone, the player must keep defending its claim, in one of two ways. Either
the first call raised, so the player stopped and `prt-supervise.sh` or crisium relaunches it, or a later call
returns the uarch claim, equal to the claim the control builds. The test exits 1 when the first call swallows the
error (it records `uarch_error` and returns `"nothing"`) and every later call returns `"nothing"` without trying
again, even though the build now succeeds.

**Requirement (THREAT_MODEL.md).**
- R4: "The honest operator observes the chain and submits its transactions within the dispute clocks. After a stop,
  it restarts from a directory that O2 guarantees and keeps defending its claim."
- Section 4: "A host fault, such as a full disk or an output channel that refuses a write, may stop the honest
  operator, ..."
- Section 3, Support: "A defect that only a support component shows is Medium when it would rate High or Critical
  in the role the component stands in for, such as ... the honest operator for an implementation of an operator".

**Run.** `bugs/run.sh R5-INVPLAYER-1`. It needs the in-tree build, the harness `baremetal-template` config and
lua-posix. It takes about 1 to 2 minutes, mostly syncing the stored clones. Temporary files go under `$TMPDIR` (or
`/tmp`) and are removed at the end.

**Expected output on audit/prt2.**
```
first call (EMFILE injected): nothing
  anomaly: uarch_error at input 0, period 0: .../prt.lua:1327: unable to create reference link from '.../entries/0/0000000000000000-8000.bin' to '.../pair/0000000000000000-8000.bin': open() failed: Too many open files
later call 1 (fault cleared): nothing
later call 2 (fault cleared): nothing
later call 3 (fault cleared): nothing
control: direct build succeeds, uarch claim root 0xf69eada33e49c234ba4d90010738994e1efbcf34441dc4dff623d88f12b36b73
VIOLATED: R4/section 4: a transient host fault (EMFILE) during the uarch claim build must stop the player or be retried; ...
run.sh: R5-INVPLAYER-1: exit 1 (bug present)
```
Exit 2 means a setup problem: a missing config, a missing lua-posix, or an injected fault that did not reach the
build.
