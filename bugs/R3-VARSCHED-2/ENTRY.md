## R3-VARSCHED-2

**Title.** The PRT transaction journal stops re-pricing a pending move once its priority fee reaches
`--max-priority-fee`, so the move's max fee stays frozen even when `--max-fee` has room.

**Severity.** Medium (a support component standing in for a Critical R4 failure of the honest operator). On the
alternative reading given under Rating, it is Low.

### Problem

`methods:fees` in the PRT transaction journal prices a replacement at the same nonce by raising both the priority fee
and the max fee by `bump_percent` (default 15%). It then returns nil whenever the raised priority exceeds
`max_priority_fee` (default 10 gwei). It does this even when the max fee that inclusion needs is far below `max_fee`
(default 100 gwei). `methods:submit` then outbids only a candidate the node no longer holds. Otherwise it returns
`{ blocked = "fee_ceiling" }`.

A replacement must raise the priority fee, so the priority cap also caps the number of replacements. A candidate signed
at the cap can never be replaced. The node suggests a tip of 10 gwei or more, so the first candidate takes the cap. One
signed at 1 gwei can be replaced about 16 times. Once the cap is reached, the candidate's max fee stays at its value
when it was signed, about twice the base fee then plus the priority. If the base fee later rises above max fee minus
priority, the honest move cannot be included or replaced. It also holds the account's nonce, which blocks every later
move of that signer. The operator's configured `--max-fee` budget would have covered inclusion.

The move stays stuck while the base fee stays high. That draws on the censorship allowance of the dispute clocks. A
journal that re-priced within `--max-fee` would lose about one inclusion. A surge that lasts longer than the allowance
makes the honest claim lose by timeout. A dishonest claim can then win, which is the completeness failure of section 1:
the honest operator "cannot respond in time".

### Component, role and area

`doc/recipes/prt-transactions.lua`, the transaction journal that `doc/recipes/prt-bridge.lua` and
`doc/recipes/crisium.lua` use to submit every PRT move. The AUDIT.md row for "The PRT player and bridge in
`doc/recipes`" gives it the role Support ("No production deployment runs the player, the bridge or the CLI"). It stands
in for the honest operator's "Submitting transactions" (section 2, honest operator's path). Area: fee pricing and
same-nonce replacement.

### Location

- `doc/recipes/prt-transactions.lua`, `methods:fees` (lines 140-154). The check at line 150 is
  `if priority > self.max_priority_fee or fee > self.max_fee or fee < base + priority then return nil end`, and it
  runs after the 15% bump of `previous.priority_fee` at line 147.
- `doc/recipes/prt-transactions.lua`, `methods:submit` (lines 192-211). The fallback re-prices only when the
  newest candidate the node holds differs from `previous`. Otherwise it returns `blocked = "fee_ceiling"`.
- Defaults are set in `M.new` (about line 305-321): `bump_blocks` 3, `bump_percent` 15, `min_priority_fee` 1 gwei,
  `max_priority_fee` 10 gwei, `max_fee` 100 gwei. `crisium.lua` passes `--max-fee` and `--max-priority-fee` through.

### Evidence and test

`bugs/R3-VARSCHED-2/` contains `test.lua` and `README.md`. The test needs no emulator, chain or network. It loads the
real `prt-transactions` module and drives it over a mock node. The mock never includes the account's transactions,
keeps every published candidate in its pool, and lets the test set the base fee and `eth_maxPriorityFeePerGas`. The
journal runs with its defaults.

- **A.** The move is first signed at a 10 gwei base fee with a 10 gwei suggested tip. It gets max fee 30 gwei and
  priority 10 gwei, which is the cap.
- **B.** The move is first signed at a 1 gwei base fee with a 1 gwei tip. The journal re-prices it 16 times, one bump
  every 3 blocks, which brings it to priority 9.358 gwei and max fee 28.07 gwei.

In both scenarios the base fee then rises to 40 gwei. The test asserts that the next `submit` publishes a nonce-0
replacement that meets three conditions:

- max fee >= base + priority;
- max fee <= `--max-fee`;
- both fees at least 10% above the old candidate's, the pool's replacement bump.

It deliberately does not assert the priority cap, because no same-nonce replacement can keep a candidate already at
the cap under it.

Run it with `bugs/run.sh R3-VARSCHED-2`. On audit/prt2 it exits 1 on every run (the reviewer ran it twice) and prints:

```
A: pending candidate at nonce 0: max fee 30.000 gwei, priority 10.000 gwei
A: tip 13, base fee 40 gwei (candidate unincludable; --max-fee 100 gwei leaves room): not re-priced: fee_ceiling -> VIOLATION
B: 16 bumps raised the priority to within 15% of the cap
B: pending candidate at nonce 0: max fee 28.073 gwei, priority 9.358 gwei
B: tip 61, base fee 40 gwei (candidate unincludable; --max-fee 100 gwei leaves room): not re-priced: fee_ceiling -> VIOLATION
VIOLATED: R4 'The honest operator observes the chain and submits its transactions within the dispute clocks': ...
run.sh: R3-VARSCHED-2: exit 1 (bug present)
```

The reviewer patched a scratch copy of the journal so that it applies the priority cap only to a first candidate and
raises a replacement's max fee to at least `min(2*base + priority, max_fee)`. The copy was loaded ahead of the tracked
file through `LUA_PATH_5_4`. With it the test exits 0:

- A re-prices to max fee 91.5 gwei, priority 11.5 gwei.
- B re-prices to max fee 90.76 gwei, priority 10.76 gwei.

Found, proved and reviewed on the campaign's primary models. No fallback was used.

### Trigger and reachability

Inputs from any valid template are irrelevant here. The trigger is the fee market during a dispute.

- **Scenario A.** The node suggests a tip of at least `--max-priority-fee` when a move is first signed. With the
  defaults, that is 10 gwei or more, which is common on some chains and during congestion. Every re-pricing of that
  move then fails. The move is stuck once the base fee exceeds max fee minus priority, about twice the base fee at
  signing. Under EIP-1559 the base fee can rise 12.5% per block, so a run of full blocks gets there in about 6 blocks.
- **Scenario B.** A move stays unmined for about 16 bump intervals, for example because it is out-tipped. After that,
  any later base-fee rise has the same effect.

Section 7 lets the adversary cause both: "Raise activity on the chain that does not belong to the application" and
"Race and reorder transactions within the chain's rules". Organic congestion does too. The mock compresses the
base-fee rise into one step. The state it creates, a pending candidate at the priority cap with its max fee below the
base fee, is the one that gradual rises reach. The stall ends only when the base fee falls back or the operator
restarts the player with a higher `--max-priority-fee`. Until then, the journal reports a `fee_ceiling` anomaly and
the signer's nonce blocks every later move.

### Rating

1. **Out of scope:** not excluded. The trigger is fee-market activity, which section 7 grants the adversary ("Raise
   activity on the chain that does not belong to the application"). No entry of the list covers it:
   - it is not a reorganization deeper than the input policy;
   - it is not a host fault;
   - it does not violate A1 to A8;
   - it is not the stall of an application.

   The goal assumes "the chain includes its transactions within the dispute clocks". A chain whose base fee is 40
   gwei includes a transaction that pays 90 gwei. Here the transaction stays out because the journal will not price it
   within the operator's own `--max-fee`, not because the chain censors it. Section 7's exclusion, "to censor the
   chain beyond the dispute clocks", is likewise about the chain.
2. **Role:** Support. AUDIT.md: "The PRT player and bridge in `doc/recipes` ... Support. No production deployment runs
   the player, the bridge or the CLI." Section 3 covers it: "A defect that only a support component shows is Medium
   when it would rate High or Critical in the role the component stands in for, such as ... the honest operator for an
   implementation of an operator." Step 2 of "How to rate": "A defect that only a support component shows is never
   above Medium." No production component in this campaign shares the code. The validator nodes are not in scope.
3. **High and Medium cases:** "A defect that only a support component shows, when section 3 rates it Medium." That
   holds if the stood-in defect would be High or Critical (step 4).
4. **Critical (stood-in role):** R4: "The honest operator observes the chain and submits its transactions within the
   dispute clocks." This is on the honest operator's path ("Submitting transactions"). Section 8: "violating any rule
   or obligation ... anywhere on the honest operator's path, is critical". Section 1, completeness failure: the
   honest operator "cannot respond in time". In the honest-operator role this is Critical, so the support component
   rates Medium.

**Alternative reading (Low).** One could read `--max-priority-fee` as part of the operator's own budget. Under that
reading, every fee-driven non-inclusion falls under the goal's premise that "the chain includes its transactions
within the dispute clocks". The stall would then be the operator's own configuration, reported loudly as
`fee_ceiling` and fixable by restarting with a higher cap. It would violate no rule, and so would be Low.

The threat model never mentions transaction fees or fee budgets. Its resources clause lists "CPU, memory and storage".
Three facts decide between the readings:

- whether the goal's inclusion premise covers only chain behaviour (censorship, liveness) or also how the operator
  prices its transactions;
- whether a priority-fee limit counts as a budget the deployment sizes, or as a tip policy below the max-fee budget;
- whether the operator's manual intervention after a reported anomaly counts as the honest operator responding.

This reviewer judges the Medium reading better supported. The pinned Dave clock model (`ClockBudgets.sol`) assumes
"Every honest action lands within `inclusion` seconds". This defect makes the operator's software, not the chain, miss
that bound while its configured `--max-fee` would meet it.

### Possible solution and risks

Apply `max_priority_fee` only to the tip a first candidate takes from the node's suggestion. Let a replacement raise
its priority by the bump even past that value, while `max_fee` stays the hard limit on what the transaction can cost.
When re-pricing, also raise the max fee to at least `min(2*base + priority, max_fee)`, so that it tracks the current
base fee and does not grow by only 15% per interval. This is the patch the reviewer checked in scratch. Another option
is a separate, larger replacement cap on the priority.

Risks:

- A replacement may pay a higher tip than `--max-priority-fee` documents. The limit's meaning changes, and
  `crisium.lua`'s option text should say so.
- The balance check at publication must still cover gas times the new max fee. It already does (`insufficient_funds`).
- The existing ceiling test in `prt-transactions-test.lua` exercises the max-fee ceiling, not the priority cap, and
  should still pass.

### Risk of not fixing it

An operator running the PRT player or bridge with the default limits can have its honest move stuck at a nonce whenever
the base fee climbs past about twice the base fee at signing. This happens immediately if the node suggests a tip of 10
gwei or more. The move stays stuck while the configured `--max-fee` still has room. Every later move of the same signer
waits behind it, across all its matches.

A competing claimant can push the base fee up by filling blocks, or the fee surge can be organic. Either way the stall
consumes the clocks' censorship allowance and can end in a timeout loss of the honest claim. The only mitigations are
outside the code:

- setting `--max-priority-fee` equal to `--max-fee`;
- reacting to the `fee_ceiling` anomaly by restarting with a higher cap before the clock runs out.

No production deployment runs this journal.
