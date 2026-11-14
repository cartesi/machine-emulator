# R6-DYNBRIDGE-2: epoch listener aborts when a within-policy reorg moves the observation head back

**Component.** PRT epoch listener in `doc/recipes`: `prt-epoch.lua` `methods:poll`, with
`prt-log-history.lua` `observe()` and `prt-rpc.lua` `head(policy)`. crisium runs it in every pass, and an
error there ends the process (`pass()` calls `listener.poll` without `pcall`).

**Defect.** Under a numeric input policy `N` (crisium `--input-policy=N`; the recipe demo passes
`PRT_INPUT_CONFIRMATIONS`, default 8), the observation head is `tip - N`. A reorg can replace only blocks
above the observation head and still end on a shorter branch. The tip number then goes down, and so does
the head. No block at or below the old head changes. `observe(head)` rewinds the history to
`min(common_ancestor, head)` and drops the logs of the still-canonical blocks between the new head and the
old one. `poll` then compares the shorter log list with the inputs it has already delivered and fails with
`assert(#logs >= #self.applied, "epoch log history was truncated")` (`prt-epoch.lua:52`).

**Requirement asserted.**
- THREAT_MODEL R4: "The honest operator observes the chain and submits its transactions within the dispute
  clocks."
- Section 4: "The honest operator acts only on history that its policy treats as final". Here the history
  the listener acted on stays canonical, so the reorg is shallower than the policy.
- Section 3 stand-in rule: the PRT player is Support and stands in for the honest operator.

The test requires that this reorg does not stop the listener, and that once the head moves forward again
every input is delivered exactly once, in order.

**What the test does.** It runs the real `prt-epoch.lua`, `prt-log-history.lua` and `prt-rpc.lua`
(`head`, `is_canonical`, `logs`), and the real ABI decoder built from the pinned Dave `InputBox` artifact
(`bugs/harness/work/dave/patched`). The JSON-RPC node is scripted in the test and answers only
`eth_getBlockByNumber` and `eth_getLogs`. The player is a stub that records what the listener delivers.
The input policy is 8:
1. Inputs 0, 1 and 2 go in blocks 10, 11 and 12, and an unrelated application's input goes in block 11.
   At tip 20 the head is 12, and all three inputs are delivered.
2. A reorg replaces blocks 19 and 20:
   - **Control:** with 2 blocks. The tip stays at 20 and the head at 12.
   - **Defect:** with 1 block. The tip moves to 19 and the head to 11. Block 12 stays canonical, and the
     test checks this.
3. The listener polls. Then input 3 is added, and the chain advances until the head passes it. The listener
   polls at each block, and the test checks that inputs 0 to 3 were each delivered once, in order.

The control must pass, or the test exits 2. The test exits 1 if the defect scenario raises or loses or
repeats an input. A minimal fix (in `poll`, return without delivering while the new head is below a
still-canonical previous head) makes it exit 0. That fix was checked on a scratch copy, not committed.

**Run.** `bugs/run.sh R6-DYNBRIDGE-2`. It takes about a second, needs no chain and no machine, and needs
only the built Lua module and the pinned Dave build's artifacts.

**Expected output on audit/prt2** (exit 1):
```
control (depth 2 -> 2 blocks): tip 20 head 12, old head 12 canonical true; poll ok; delivered {0:input-0, 1:input-1, 2:input-2, 3:input-3}
shorter branch (depth 2 -> 1 block): tip 19 head 11, old head 12 canonical true; poll ERROR: .../doc/recipes/prt-epoch.lua:52: epoch log history was truncated
VIOLATED: R4/section 4: a reorganization shallower than the input policy, which leaves every block the listener acted on canonical (old head 12), stopped the listener: .../prt-epoch.lua:52: epoch log history was truncated
run.sh: R6-DYNBRIDGE-2: exit 1 (bug present)
```
