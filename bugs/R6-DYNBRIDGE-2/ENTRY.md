## R6-DYNBRIDGE-2

**Title.** PRT epoch listener aborts crisium with "epoch log history was truncated" when a reorganization shallower
than a numeric input policy ends on a shorter branch, so the observation head moves back over blocks that are still
canonical and whose inputs it already delivered.

**Severity.** Medium (preferred: Support component standing in for the honest operator, whose chain observation would
crash on a within-policy chain event) / Low (if a crash that a relaunch recovers violates no rule, because R4 provides
for restarts after a stop).

### Problem

Under a numeric input policy `N` (crisium `--input-policy=N`, which `prt-rpc.lua` `M.policy` accepts as "a
nonnegative block depth"; the recipe demo passes `PRT_INPUT_CONFIRMATIONS`, default 8), the listener observes up to
`head = tip - N`. A reorganization can replace only blocks above that head and still end on a branch with fewer blocks.
The tip number then goes down, and the head goes down with it, although every block at or below the old head stays
canonical. `prt-log-history.lua` `observe(head)` rewinds to `math.min(common_ancestor(self), head)`, so it drops the
logs of the still-canonical blocks between the new head and the old one. `prt-epoch.lua` `methods:poll` then compares
the shorter log list with the logs it has already applied and fails with
`assert(#logs >= #self.applied, "epoch log history was truncated")`. crisium calls `listener.poll` in `pass()` without
`pcall`, so the error ends the player process: the honest operator's implementation stops observing the chain, delivering
inputs and answering its disputes, on a chain event that its own policy says it must tolerate. Nothing it acted on was
replaced. If nothing relaunches it, it stays down, and any claim may win its open epochs. Under `prt-supervise.sh`, it
restarts from its stored state and spends the relaunch time out of the dispute clocks.

### Component, role and area

The PRT player in `doc/recipes`, specifically the epoch listener (`prt-epoch.lua`) and its log history
(`prt-log-history.lua`), run by `crisium.lua`. The AUDIT.md table gives it the role Support: "The PRT player and bridge in
`doc/recipes`, the `cartesi-machine` CLI, and the Lua helper libraries ... | Support. No production deployment runs the
player, the bridge or the CLI." It stands in for the honest operator. The areas are "Observing the chain" and "Delivering
inputs" on the honest operator's path.

### Location

- `doc/recipes/prt-epoch.lua`, `methods:poll`: `self.chain:head(self.input_policy)` (line 30), `history:observe` (line
  34), and the assert at line 52.
- `doc/recipes/prt-log-history.lua`, `methods:observe` (lines 54-59), which calls `rewind(self, math.min(common_ancestor(self), head))`.
- `doc/recipes/prt-rpc.lua`, `methods:head` (lines 113-126): `number - policy` for a numeric policy.
- `doc/recipes/crisium.lua`, `pass()` (line 300): `measure("poll", listener.poll, listener)` with no error handling. The
  main loop does not catch errors either.

### Evidence and test

`bugs/R6-DYNBRIDGE-2/` contains `test.lua` and `README.md`. Run it with `bugs/run.sh R6-DYNBRIDGE-2`. It takes about a
second and needs no chain and no machine. The test runs the real `prt-epoch.lua`, `prt-log-history.lua`, the `prt-rpc.lua`
client (`head`, `is_canonical`, `logs`) and the ABI decoder built from the pinned Dave `InputBox` artifact
(`bugs/harness/work/dave/patched`). The JSON-RPC node is scripted in the test and answers `eth_getBlockByNumber` and
`eth_getLogs`. A stub player records the inputs the listener delivers. With input policy 8, inputs 0 to 2 go in blocks 10
to 12, plus another application's input in block 11. At tip 20, the head is 12 and all three inputs are delivered. Then
blocks 19 and 20 are replaced:

- by 2 blocks (the control). The tip stays at 20. The listener keeps polling, and inputs 0 to 3 are each delivered once.
  If the control fails, the test exits 2.
- by 1 block (the defect). The tip moves to 19 and the head to 11. The test checks that block 12 is still canonical with
  its original hash. Then the listener polls.

It prints, on audit/prt2 (the listener's stderr progress lines omitted), and exits 1:

```
control (depth 2 -> 2 blocks): tip 20 head 12, old head 12 canonical true; poll ok; delivered {0:input-0, 1:input-1, 2:input-2, 3:input-3}
shorter branch (depth 2 -> 1 block): tip 19 head 11, old head 12 canonical true; poll ERROR: .../doc/recipes/prt-epoch.lua:52: epoch log history was truncated
VIOLATED: R4/section 4: a reorganization shallower than the input policy, which leaves every block the listener acted on canonical (old head 12), stopped the listener: .../doc/recipes/prt-epoch.lua:52: epoch log history was truncated
run.sh: R6-DYNBRIDGE-2: exit 1 (bug present)
```

The reviewer re-ran it twice and got exit 1 both times. On a scratch copy of `prt-epoch.lua`, `poll` was changed to
return `nil` without delivering while the new head is below a previous head that is still canonical. With that copy the
test exits 0, and all four inputs are delivered once, in order. So the test asserts the required behavior and is not
an artifact of the scripted node. Opus 5.5 found, proved and reviewed it. No fallback model was used.

### Trigger and reachability

No input sequence or guest is needed. The trigger is a chain event: a reorganization whose fork point is above the
listener's observation head and whose new branch has fewer blocks than the one it replaces. On proof-of-stake Ethereum,
fork choice goes by attestation weight, not by length, so a short reorganization can end on a lower block number. The
event stops the listener only when an applied log of the epoch (an `InputAdded` for the application, or a consensus log
the listener follows) lies in the blocks between the new head and the old one. With a head that moves back by one block,
that block is the old head's. An application that receives inputs regularly meets this sooner or later. The listener of
every open, unsealed epoch is exposed, the sentinel's as well as the validator's. With the default `finalized` policy (and normally with
`safe`), the head does not move back unless the chain fails beyond the policy, so the defect needs a
numeric policy. crisium documents that option, and the recipe demo uses it.

### Rating

1. Out of scope: no exclusion applies. "Reorganizations of the chain deeper than the operator's input policy (section
   4)" does not apply, because the reorganization has depth 2 under a policy of 8. Section 4's "Acting on history before
   it is final, and recovering when that history is replaced, is outside this model" does not apply either. The listener
   acted only on blocks up to the old head, which had the policy's depth when it acted, and none of them was replaced.
   The trigger is "data relayed by the node from others", which section 4 lists as untrusted, not a call to the machine
   API or a stored directory.
2. Role: the component is the PRT player's epoch listener, which is Support by the AUDIT.md table. Section 3 says: "A
   defect that only a support component shows is Medium when it would rate High or Critical in the role the component
   stands in for, such as ... the honest operator for an implementation of an operator or a tool that computes claims."
   This clause covers the component: crisium is an implementation of an operator. The settled reading applies: "When a
   Support component (the PRT player, the CLI) fails on its own operator path, rate it under section 3's stand-in rule."
   Section 8 step 2: "A defect that only a support component shows is never above Medium."
3. High and Medium cases: the case that fits is "A defect that only a support component shows, when section 3 rates it
   Medium". No other High or Medium case fits.
4. Critical, in the stood-in honest-operator role: the defect violates R4, "The honest operator observes the chain and
   submits its transactions within the dispute clocks", on the honest operator's path ("Observing the chain", "Delivering
   inputs"). It also matches the listed Critical case "A crash, hang, out-of-bounds read, or unbounded allocation caused
   by data from other parties that the honest operator must process". The blocks above the policy's depth, and the tip
   number derived from them, are chain data that section 4 trusts only "as far as the operator's input policy confirms
   it", and the operator must read them to observe the chain. Critical in the stood-in role makes it Medium for this
   Support component.

Two readings give different classes. Under reading A (preferred), the crash itself is the violation. The listed Critical
crash case has no "permanent" condition, and R4's restart clause is about recovering from stops, not a license to stop on
a routine chain event. Under that reading it is Medium. Under reading B, a crash that a relaunch recovers violates no rule,
because R4 provides "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim". Under
that reading it is Low. Two facts would decide. First, whether the deployment always runs the player under a supervisor:
crisium alone exits and stays down, and only `prt-supervise.sh` relaunches it. Second, how the relaunch cost (reopening
every open epoch, refetching logs, reloading stored players) and how often the event recurs compare with the dispute
clocks (A7).

### Possible solution and risks

In `methods:poll`, remember the last observed head and its hash. When a new head is below a previous head that is still
canonical, return `nil` without delivering, and keep the history. Alternatively, have `observe` keep the logs up to the
newest canonical block it already holds, and have `poll` deliver only up to the new head. Either way, a reorganization
that does replace applied blocks must still take the existing reset and "epoch history changed" paths. The risk is
hiding a real replacement. The canonicity check on the previous head, which the scratch fix used, prevents that, and the
test checks that every input is then delivered exactly once, in order.

### Risk of not fixing it

An operator that runs crisium with a numeric `--input-policy` loses its player on any short reorganization that lowers
the tip while an applied input sits in the blocks the head moves back over. No adversary has to act. Without a
supervisor, the player stays down and stops defending its open epochs. With `prt-supervise.sh`, every such event costs a
relaunch out of the dispute clocks. The mitigations outside the code are to use the default `finalized` policy (or `safe`)
and to always run the player under `prt-supervise.sh`.
