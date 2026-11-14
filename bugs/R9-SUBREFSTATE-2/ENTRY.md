## R9-SUBREFSTATE-2

**Title.** The PRT referee model in `doc/recipes` binds a claim to the TCP connections that posted it. An honest player that stops and restarts comes back on a new connection, is never again asked about its claim, and the claim loses by timeout.

**Severity.** Critical (preferred: a defect in which claim a timeout decides, rated as a deployed referee, A7 with R4's restart clause). Medium under the alternative reading that this "only ... stalls the model" and is rated as support. See Rating.

### Problem

In the referee model, the holders of a claim are the connection objects whose claim responses were accepted.
`partition_claims` (`doc/recipes/prt.lua`) calls
`subscribe_connection(subscription_hash(tournament_id, claim), response.connection)` for each accepted claim
response. The only other subscription is `accept_subscribers` (`doc/recipes/game-transport.lua`), which subscribes
the players announced before admission closes to the initial state hash. No code path ever adds a connection to a
claim's subscription later. A player that announces after admission (`announce`) gets only `is_player`.

Every request about a claim goes to that fixed set of connections. These are `reveal_bisection` (`reveal_divergence`),
`seal_divergence`, `win_match_by_timeout` (`emit_win_match_by_timeout`), `commit_uarch_claim` (`open_uarch_tournament`),
`prove_state_transition` (`settle_uarch_state_hash`) and `propagate_uarch_result`. `dispatch_request` fixes the
request's audience to those connections. `accept_scheduled_response` drops any response from a connection outside
`future.audience`.

A stored honest player that stops and restarts from its epoch directory necessarily reconnects on a new connection.
It holds the claim's tree and can answer every request about it, but it is not a holder. It is not asked, and its
answers would be dropped. It cannot post the claim again, because claim collection is closed. When the claim comes on
turn, nobody answers. The opponent wins by timeout and the honest claim is eliminated. With one dishonest opponent, a
fabricated final state settles.

The manual describes the opposite. "a claim does not belong to the player that posted it. Every request concerns a
claim, and any holder of that claim may answer it. The answer must verify against the claim's own commitment, so the
sender does not matter. Every honest player computes the same claim, and that claim survives as long as anyone defends
it." It also says that "A stored player keeps its machines, inputs, and outputs in an epoch directory, and reopens it
after a crash". The deployed referee does not bind moves to a sender either. In the pinned Dave `Tournament.sol`,
`advanceMatch` checks only the nodes against the match state, not `msg.sender`, and an honest node that restarts
keeps its keys anyway.

This breaks the goal's completeness side. Section 1 says "If the honest claim is eliminated, a dishonest claim can
win." The test shows exactly that: the tamperer's claim, with a different final state, settles.

Today a crash (an EOF without a `done` reply) crashes the referee model first. That is the confirmed issue
R3-VARREFMODEL-2. This issue is separate. It is reached with an announced departure today, and it becomes the outcome
of every restart once R3-VARREFMODEL-2 is fixed by dropping the dead connection.

### Component, role and area

The PRT referee model in `doc/recipes` (`prt.lua referee` over `game-transport.lua`). AUDIT.md table: "The PRT referee
model in `doc/recipes` | Referee model". Area: claim holders and request audiences (who may answer for a claim).

### Location

- `doc/recipes/prt.lua`: `partition_claims` (230-258, the only claim subscription, l.245); requests addressed to
  claim holders in `emit_win_match_by_timeout` (368-381), `settle_uarch_state_hash` (409-), `open_uarch_tournament`
  (461-, l.476-480), `propagate_uarch_result` (514-, l.523-525), `reveal_divergence` (602-, l.608-611) and
  `seal_divergence` (633-, l.638-641).
- `doc/recipes/game-transport.lua`: `announce` (530-545, a late player gets no subscription),
  `subscribe_connection` (623-630), `get_subscribers` (634-656), `dispatch_request` (826-837, fixed audience),
  `accept_subscribers` (900-917), `accept_scheduled_response` (925-939, the audience check at l.933).

### Evidence and test

`bugs/R9-SUBREFSTATE-2/` contains the following.

- `test.sh`: the test, run by `bugs/run.sh R9-SUBREFSTATE-2` (about 30 s). It runs two real tournaments with the
  in-tree `prt.lua referee` over the same epoch: the harness's `baremetal-template` with three inputs. Each has two
  claimants, joined in this order: the honest stored player (`honest-first.lua`) and
  `prt-dishonest.lua tamperer 1 0`, which corrupts its own execution of input 1. It uses free loopback ports, starts
  no chain and kills every process it starts.
  - Control: the honest player runs unchanged. The test requires the honest claim to win (otherwise exit 2).
  - Restart: at its claim's first `reveal_bisection`, the first incarnation stops with its reply outstanding, so the
    referee's logical clock cannot advance. A second incarnation (`honest-restarted.lua`) is started on the same
    epoch directory. It reopens the sealed epoch and checks that it holds the claim's tree and can open its root. The
    test waits until the referee's trace (`PRT_GAME_TRACE`) shows it read the new connection's announcement. Only
    then does the first incarnation leave with an announced `done` reply, so the referee does not crash on an EOF
    (R3-VARREFMODEL-2). The restarted player is connected before any block passes.
  - Required (A7, R4): the honest claim still wins. Exit 0 if it does, 1 if it loses, 2 on a setup error.
- `honest-first.lua`: `prt.lua honest ... <epoch-directory>` as a stored player, plus two hooks. It records the claim
  it posts and, in restart mode, stops at the first `reveal_bisection`.
- `honest-restarted.lua`: the same stored player on the same epoch directory. It checks that it holds the claim and
  logs every request it receives.
- `fix-check.sh` (not run by `run.sh`; run after `. bugs/env.sh`). It patches a copy of `doc/recipes` so that a
  player announcing after admission joins the audience of open and later claim requests, and so that the honest
  handlers answer `nothing` for a claim they do not hold. It then runs `test.sh` against the copy.

The reviewer re-ran `bugs/run.sh R9-SUBREFSTATE-2` twice on audit/prt2. Both runs exit 1 with identical output:

```
control: tournament:
  Round 1, match 1, at the mcycle level: claim 0x84cc13c6... against claim 0x29040379....
  Match 1: claim 0x84cc13c6... wins.
control: the honest claim 0x84cc13c66a48e339ff1e479d07dab73c60d8a2fe4af36ffa7611e61a3eb128f9 wins (no restart), final state 0xbab85ef1f80cc29c18685068c952c603813b2f2df1055fbb88cbcec4a2872f0d
restart: first incarnation stops at reveal_bisection(position=0, height=62) of claim 0x84cc13c66a48e339ff1e479d07dab73c60d8a2fe4af36ffa7611e61a3eb128f9
  (its reply is outstanding, so the referee's logical clock cannot advance)
restart: second incarnation reopened the epoch directory, holds claim 0x84cc13c66a48e339ff1e479d07dab73c60d8a2fe4af36ffa7611e61a3eb128f9, and is connected
restart: first incarnation left with an announced departure (done)
restart: tournament:
  Round 1, match 1, at the mcycle level: claim 0x84cc13c6... against claim 0x29040379....
  Match 1: claim 0x29040379... wins.
  Nobody opened claim 0x84cc13c6.... Claim 0x29040379... claims a timeout win.
restart: requests about the claim received by the restarted player: 0
  2 honest (restarted): received prove_output 0x54685bd0492489f7f4d741b9a7bb0a67a57e393cb6ff7a1692d01eef300a57b4
  1 honest (restarted): received prove_outputs_merkle_root 0x540b26c794ae6ebb12d76d49225eb27dbf3cb69329fdcbc84772cb48de29a407
FAIL (A7/R4): the honest claim 0x84cc13c66a48e339ff1e479d07dab73c60d8a2fe4af36ffa7611e61a3eb128f9 lost after its player restarted within its clock
  winner: the tamperer's claim 0x2904037976d7749c28b8b96a66dcd08adc5f47fe329589e26d142c1236d66953, final state 0x540b26c794ae6ebb12d76d49225eb27dbf3cb69329fdcbc84772cb48de29a407 (honest final state 0xbab85ef1f80cc29c18685068c952c603813b2f2df1055fbb88cbcec4a2872f0d)
  A7: "No rule of the referee may make the honest claim lose by timeout while it acts within its own clock."
  R4: "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim."
run.sh: R9-SUBREFSTATE-2: exit 1 (bug present)
```

The restarted player receives only `EVERYONE` requests, the output proofs for the tamperer's settled state. The
tamperer's fabricated final state settles. The reviewer also ran `fix-check.sh`, which exits 0. Against the patched
copy, the restarted player receives 33 requests about its claim. It opens the pending nodes, builds its uarch claim and
proves the disputed transition, and the honest claim wins with final state `0xbab85ef1...`. So the test fails for this
defect and passes once it is fixed. The test asserts only the outcome that A7 requires, and no wall-clock threshold
decides it.

### Trigger and reachability

No adversary action beyond posting a dishonest claim is needed. The trigger is the honest operator's own stop and
restart, which is on the honest operator's path ("Restarting after a stop (O2)", section 2) and which the manual's
stored player is documented to support ("reopens it after a crash"). Any match in which the honest claim comes on turn
after the restart reaches it. That holds for every epoch with at least one claim that disagrees with the honest one.
The restarted player reloads a sealed epoch directory that the first incarnation finished writing, so O2 does not
exclude it. Today the stop must be an announced departure (`done`), since an unannounced EOF crashes the referee model
(R3-VARREFMODEL-2). Once that crash is fixed by dropping dead connections, a crash or kill reaches this issue too.

### Rating

1. Out of scope: no. The exclusion "Defects that need the deployment to violate one of A1 to A8, unless ... an
   implementation of the referee model is what violates it (section 3)" does not apply, because the referee model is
   what violates A7. The O2 exclusion ("Defects that need the honest operator to reload a stored directory that O2
   does not guarantee") does not apply. The restarted player reopens a sealed epoch directory, and the defect does
   not depend on its contents: the referee never asks the new connection anything about the claim. No other exclusion
   concerns restarts or the referee's choice of senders.
2. Role: the PRT referee model in `doc/recipes`, role "Referee model" (AUDIT.md table). Section 3 covers this
   component: "A defect in what it accepts or derives is rated as if a deployed referee had it. Which claim a timeout
   or an elimination decides is part of what it derives." The defect is in what it accepts (answers only from the
   posting connections) and in which claim a timeout decides (the honest one). The support clause, "A defect that
   only changes how long a claim may take to respond, or only crashes or stalls the model, even when that stops other
   matches (A8), is rated as support", does not fit. The model neither crashes nor stalls. It runs to a verdict and
   settles the wrong claim. If the manual's model is read as binding a claim to its posters ("every player that posted
   one becomes a holder of it"), section 3 still applies: "unless the manual's model itself violates one of A1 to A8;
   then the manual is the defect, rated as a defect of the referee model". The binding is not among the
   simplifications the manual lists ("The model simplifies the PRT contracts in a few ways ..."), so it is not
   excused as non-normative.
3. High and Medium cases: none fits. It is not a verifier on unreachable states, a constant-factor cost, or a
   persistence failure. Section 8's Medium "A defect that only a support component shows, when section 3 rates it
   Medium" does not apply, because the component is the referee model and section 3 rates this defect as a deployed
   referee's.
4. Critical: it violates A7 at a reachable state on the honest operator's path. A7 says "No rule of the referee may
   make the honest claim lose by timeout while it acts within its own clock." The restarted honest player is connected
   and holds the claim before any block of the claim's clock passes, and the claim loses by timeout. R4 requires the
   operator to be able to do exactly this: "After a stop, it restarts from a directory that O2 guarantees and keeps
   defending its claim." A referee with this acceptance makes that impossible. Section 8: "violating any rule or
   obligation at a reachable state, or anywhere on the honest operator's path, is critical." It also produces the
   section 1 completeness failure: "If the honest claim is eliminated, a dishonest claim can win."

Alternative reading: if the timeout loss is read as the model "only ... stall[ing]" for want of an answer, it is rated
as support. That gives Medium under section 3's stand-in rule, since a deployed referee would rate Critical. The fact
that decides is whether the honest operator "acts within its own clock" when it is ready and connected but the
referee gives it no channel. The test shows the referee reaching a verdict against the honest claim, not a stall,
which supports the Critical reading. A Low reading would need per-connection holders to be a non-normative
simplification of the manual, and the manual's list of simplifications does not include it.

### Possible solution and risks

Stop binding claims to connections. One option is to address claim requests to every live player, or to every player
that declares the claim, and to accept the first response that validates against the claim's commitment, whoever sent
it, as the manual and Dave do. Another is to let a connection that announces after admission subscribe to a claim's
hash once it shows that it holds the claim, for example by opening its root. The audience of requests already
outstanding must also grow, so that a player that reconnects mid-request can still answer it. `fix-check.sh` sketches
the first option. The honest handlers must then answer `nothing` for a claim whose tree they do not hold. Risks: the
narration and the transcript order must stay deterministic when the audience grows, and late joiners must not be able
to delay the block barrier indefinitely (A8). Fixing R3-VARREFMODEL-2 by dropping dead connections is needed for a
crash restart to reach the fix.

### Risk of not fixing it

A deployment that implemented the model's acceptance rule would let any dishonest claim win against an honest
operator that restarts during a dispute (an upgrade, a crash, a host reboot). The adversary only needs to post a
disagreeing claim and wait. Running several independent honest operators on the same claim mitigates it while at
least one of them never restarts. The manual's model, which Dave and the Lua bridge are checked against, also stays in
contradiction with its own statement that "the sender does not matter".
