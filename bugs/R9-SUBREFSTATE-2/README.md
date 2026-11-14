# R9-SUBREFSTATE-2: the referee model binds a claim to the connections that posted it, so a restarted honest player can never answer for its claim again

Component: referee model, `doc/recipes/prt.lua referee` over `doc/recipes/game-transport.lua`.
`partition_claims` subscribes only the connections whose claim responses were accepted
(`subscribe_connection(subscription_hash(tournament_id, claim), response.connection)`). The only other
subscription is `accept_subscribers`, which covers players announced before admission closes. Every later
request about a claim goes to that fixed audience: `reveal_bisection`, `seal_divergence`,
`win_match_by_timeout`, `commit_uarch_claim` and `prove_state_transition`. `accept_scheduled_response`
also accepts answers only from that audience (`future.audience[response.connection]`).

A player that stops and restarts comes back on a new connection. That connection is not a holder of its
claim, so it can never be asked about the claim, and its answers are not accepted. The claim then loses by
timeout. The manual says otherwise (doc/README.md, "Permissionless refereed tournament"): "a claim does
not belong to the player that posted it. Every request concerns a claim, and any holder of that claim
may answer it. The answer must verify against the claim's own commitment, so the sender does not
matter."

## What is asserted

The test runs two real tournaments over the same epoch: the harness's bare-metal `baremetal-template`,
with three inputs. Each tournament has two claimants, joined in this order:

1. The honest player: `honest-first.lua`, which is `prt.lua honest <addr> <hash> honest <epoch-directory>`,
   a stored player.
2. `prt-dishonest.lua tamperer 1 0`. It corrupts its own execution of input 1, so its claim ends in a
   different final state.

Each run has one match. The honest claim is claim 1 and is on turn first.

* **control**: the honest player runs unchanged. Setup requirement: the honest claim wins.
* **restart**: at the honest claim's first `reveal_bisection` request, the first incarnation stops. Its
  reply stays outstanding, so the referee cannot advance its logical clock. The test then does three
  things while the clock is frozen:
  1. It restarts the player from its epoch directory as a new process and a new connection,
     `honest-restarted.lua`. This is `prt.lua honest ... <epoch-directory>` plus logging. The new
     process reopens the sealed epoch and checks that it holds the honest claim's tree and can open its
     root.
  2. It waits until the referee has read the new connection's announcement. The referee runs with
     `PRT_GAME_TRACE`.
  3. Only then does the first incarnation leave, with an announced `done` reply. An unannounced EOF
     would crash the referee instead (R3-VARREFMODEL-2).

  So the restarted player is connected before any block passes. It acts within the honest claim's clock.

  **Required:** the honest claim still wins.

Requirements (THREAT_MODEL.md):

> **A7.** ... No rule of the referee may make the honest claim lose by timeout while it acts within its own
> clock.

> **R4.** ... After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim.

Section 3: "Which claim a timeout or an elimination decides is part of what it derives."

No wall-clock threshold decides the result. Ordering is enforced by marker files, by the referee's own
trace, and by the referee's block barrier. The outcome is read from the referee's narration (`verdict`,
`tournament`, `match_1`).

## Run

```sh
bugs/run.sh R9-SUBREFSTATE-2     # about 30 s; KEEP=1 keeps the run directories (printed path)
```

The test needs the in-tree emulator and `bugs/harness/work/configs/baremetal-template`. It uses free
loopback ports and starts no chain. It kills every process it starts (each in its own process group).

Exit codes:

* 0: the honest claim wins after the restart (fixed).
* 1: it loses (bug present).
* 2: setup error. Examples: the control is not won by the honest claim, the honest claim is never asked
  to open a node, or the restarted player cannot reopen its directory or does not connect.

## Expected output on audit/prt2

```
control: tournament:
  Round 1, match 1, at the mcycle level: claim 0x84cc13c6... against claim 0x29040379....
  Match 1: claim 0x84cc13c6... wins.
control: the honest claim 0x84cc13c6...28f9 wins (no restart), final state 0xbab85ef1...
restart: first incarnation stops at reveal_bisection(position=0, height=62) of claim 0x84cc13c6...28f9
  (its reply is outstanding, so the referee's logical clock cannot advance)
restart: second incarnation reopened the epoch directory, holds claim 0x84cc13c6...28f9, and is connected
restart: first incarnation left with an announced departure (done)
restart: tournament:
  Round 1, match 1, at the mcycle level: claim 0x84cc13c6... against claim 0x29040379....
  Match 1: claim 0x29040379... wins.
  Nobody opened claim 0x84cc13c6.... Claim 0x29040379... claims a timeout win.
restart: requests about the claim received by the restarted player: 0
  2 honest (restarted): received prove_output 0x5468...
  1 honest (restarted): received prove_outputs_merkle_root 0x540b26c7...
FAIL (A7/R4): the honest claim 0x84cc13c6...28f9 lost after its player restarted within its clock
  winner: the tamperer's claim 0x29040379..., final state 0x540b26c7... (honest final state 0xbab85ef1...)
run.sh: R9-SUBREFSTATE-2: exit 1 (bug present)
```

After the restart, the restarted player receives only `EVERYONE` requests: the output proofs for the
tamperer's settled state. It receives no request about its claim. The tamperer's fabricated final state
settles.

## Check against a fix (not run by run.sh)

`fix-check.sh` (run it after `. bugs/env.sh`) copies `doc/recipes` to a temp directory and patches the copy
in two places:

* `game-transport.lua`: a player that announces after admission joins the audience of every open
  first-valid request (and is sent that request), and of every later subscription request.
* `prt.lua`: the handlers answer `nothing` for a claim whose tree the player does not hold.

It then runs `test.sh` against the copy, which exits 0. In that run the restarted player opens the
pending node and builds its uarch claim (`Match 1.1`). It also proves the disputed transition, and the
honest claim wins `Match 1`.

## Files

* `test.sh`: orchestration. The process handling is adapted from `bugs/R3-VARREFMODEL-2/test.sh`.
* `honest-first.lua`: the honest stored player. It records its claim and, in restart mode, stops at its
  first `reveal_bisection` and leaves with `done` on a signal.
* `honest-restarted.lua`: the restarted honest stored player on the same epoch directory. It checks that
  it holds its claim and logs the requests it receives.
* `fix-check.sh`: an optional check of the test against a sketch of a fix.
