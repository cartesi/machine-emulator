## R9-SUBREFSTATE-1

**Title.** The PRT referee model in `doc/recipes` stops accepting output proofs for good once every player connected at the latest `prove_output` request has answered without a new valid output. A valid proof of another committed output is then never heard.

**Severity.** Critical (preferred: a defect in what the referee model accepts, rated as a deployed referee under A5). Medium under the alternative reading that this "only ... stalls the model" and is rated as support. See Rating.

### Problem

After the tournament, `wait_for_outputs` (`doc/recipes/prt.lua`) settles the outputs Merkle root. It then loops: it
issues `request_first_valid(EVERYONE, EVENTS.prove_output, ...)` and waits `FOREVER` for one valid output that it has
not accepted yet. The transport (`doc/recipes/game-transport.lua`) fixes each request's audience to the player
connections that are live when the request is dispatched (`dispatch_request`). Each audience member answers that
request once. `accept_scheduled_response` drops any response from a connection outside `future.audience`. Once every
audience member has answered, `step_time` finds no logical-time boundary: there is no deadline, no target block and no
pending scheduled block. So the clock never advances, no `advance_time` is sent (the only channel that carries pushed
responses), and no new request is issued. A line from a connection with no current request is read and discarded
(the reader matches `message.id` against `expected_id`, l.586). The comment of the transport states the design: "Only
an accepted response resolves a first-valid future, even when all its holders answer "nothing" or leave."

This freeze happens in the model's normal flow. The honest player's `event_handler.prove_output` always offers the
epoch's last output (`prt.lua` l.2010-2011). Its first offer is accepted. The loop then asks it again, it offers the
same output again, the validator refuses it as already accepted, and the model freezes. From then on, no valid proof
of any other output that the settled state commits to can be presented. That holds for a party that connects later
(the `EVERYONE` audience would include it, but no request is ever issued again), for an honest player that restarts on
a new connection, and for an audience member that would offer another output later. The manual's PRT section says
"The referee then accepts output proofs against that root, and the player chooses which output to offer ... The
referee waits for output proofs indefinitely". The `prt.lua` comment says "Anyone may answer, since every offer is
validated against the settled hash". The deployed referee (rollups-contracts output validation) accepts a valid proof
from anyone at any time.

This violates A5: "Conversely, the referee accepts every output that the settled state commits to, whenever its valid
proof is presented. No party can make it stop accepting them." A deployed referee with this behavior would make every
output of an epoch other than those offered in the first request rounds permanently unprovable. A party could also
cause the freeze before an output it wants suppressed is offered.

### Component, role and area

The PRT referee model in `doc/recipes`. Its AUDIT.md role is "Referee model". The area is output acceptance after
settlement (`wait_for_outputs`) and the referee transport's request audience, response acceptance and logical clock.
Section 3 says: "What it authenticates or derives under A1 to A5 is its own, whichever library does the work". So
`game-transport.lua`'s server is part of the referee model here.

### Location

- `doc/recipes/prt.lua`: `wait_for_outputs` (l.774-802: `request_first_valid(EVERYONE, EVENTS.prove_output, ...)` and
  `output_proof:wait_at_most(FOREVER)` at l.786-796); `run_referee` (l.816-824); `event_handler.prove_output`
  (l.2010-2011, always the last output).
- `doc/recipes/game-transport.lua`: `dispatch_request` (l.826-838, fixed `future.audience`), `get_players` (l.659),
  `accept_scheduled_response` (l.925-978, `not future.audience[response.connection]` drops the response),
  `step_time` (l.1011-1140: boundaries only from deadlines, target blocks and integer pending blocks; `next_block` at
  l.1126 returns nothing, so no `advance_time` is sent), the adopt reader (l.586-598, a line without the current
  request id is discarded).

### Evidence and test

`bugs/R9-SUBREFSTATE-1/` contains `test.lua` (the test), `README.md` (the prover's notes) and this entry. Run it with
`bugs/run.sh R9-SUBREFSTATE-1`. It takes about 3 s and needs the in-tree build and
`bugs/harness/work/configs/baremetal-template`.

The test builds a settled state from the harness's `baremetal-template` (a valid template running `emit-output.bin`)
after two accepted advance inputs. That state commits to outputs 0 and 1. It builds the outputs-root proof (iflags_Y,
htif_tohost, tx-buffer word) and both output proofs with the emulator. It checks them first with the model's own
validators (`game-output.lua`). It then runs the shipped `wait_for_outputs`, taken from the `prt.lua` closures, on the
shipped referee server (`prtu.new_server`, i.e. `game-transport.lua`). It drives the same loop as `server:run`
(`step_time` and dispatcher steps) and stops when nothing can happen (no runnable coroutine, no clock progress, no
socket readiness for 1 s), or after a step budget. Players are coroutines on the same dispatcher that talk over real
loopback sockets and encode their answers with `prtu.answer_event`. The honest player answers as
`event_handler.prove_output` does, with output 1. A control scenario connects a presenter of output 0 before
settlement and requires output 0 to be accepted, and the test exits 2 if the control fails. The tested scenario
connects the presenter after the honest player's repeated offer has been refused. The presenter answers any
`prove_output` with output 0 and pushes it under every open request id on `advance_time`. The test requires output 0 to
be accepted.

On audit/prt2 (61ac211) it prints the following and exits 1 (three runs by the reviewer, all identical):

```
settled state 0x73bee34a60c13ad2519d6551a3d89318e1ca60fe1eb612f815c6c54a97b1f37f commits to outputs 0 and 1 (outputs root 0xda25fcdcfa2cc35ac633e3f33345f7616fdcf832a7101f6f91dc15f85e47c2c4)
referee accepted output 1
referee accepted output 0
[control] phase 1: condition at block 3; honest asked prove_output 2 times; accepted {1,0}
[control] presenter got 6 events (prove_output 2, advance_time 3); accepted {1,0}
referee accepted output 1
[late] phase 1: quiescent at block 3; honest asked prove_output 2 times; accepted {1}
[late] phase 2: quiescent; block 3 -> 3; presenter connected=true
[late] presenter got 0 events (prove_output 0, advance_time 0); accepted {1}
VIOLATED: A5: the referee accepts every output that the settled state commits to, whenever its valid proof is presented; no party can make it stop accepting them (valid proof of output 0 presented after the honest player's repeated offer of output 1)
run.sh: R9-SUBREFSTATE-1: exit 1 (bug present)
```

The presenter is connected and announced as a player, but the clock stays at block 3 and it receives no event. Output
0 is never accepted. The control shows that the proofs, players and driver work. A fix that keeps output acceptance
open (for example, one that re-issues requests to the current players in later blocks) makes the test pass. The
reviewer did not modify the test. Opus 5.5 hunted, proved and reviewed it, with no fallback.

### Trigger and reachability

No adversary is needed. Once the tournament has a winner, the shipped honest player's second offer of its last output
causes the freeze. Any set of players causes it once each has answered without a new valid output. The state is the
model's ordinary end state for every epoch whose winner exists, from any valid template. Any party, including an
honest party restarting (R4: "After a stop, it restarts ... and keeps defending its claim") or a user who wants to
prove another output, is then refused. An adversary connected before settlement can also cause the freeze early by
answering with invalid offers alongside the honest player.

### Rating

1. Out of scope: no. The exclusion "Defects that need the deployment to violate one of A1 to A8" carves out "unless an
   implementation of the referee model is what violates it (section 3)", and here the referee model itself violates
   A5. It is not "The stall of an application that halts, yields manually with a reason other than accepted or
   rejected, or never yields". The settled state yields with the accepted reason and commits to both outputs. It does
   not need an untrusted party to call the machine API. The simplifications the manual lists for the model ("The model
   simplifies the PRT contracts in a few ways ...") do not include this, and section 5 makes them non-normative anyway.
2. Role: the PRT referee model in `doc/recipes`, role "Referee model" (AUDIT.md table). Section 3: "A defect in what
   it accepts or derives is rated as if a deployed referee had it", and "What it authenticates or derives under A1 to
   A5 is its own, whichever library does the work". This clause covers the component, since the request audience and
   response acceptance of `game-transport.lua` decide which output proofs the model accepts. Counter-clause: "A defect
   that only changes how long a claim may take to respond, or only crashes or stalls the model, even when that stops
   other matches (A8), is rated as support."
3. High and Medium cases: under the preferred reading none applies. It is not a verifier on unreachable states, not a
   trailing-data case, and not a persistence or hash-integrity case. Under the stall reading, the Medium case applies:
   "A defect that only a support component shows, when section 3 rates it Medium". Section 3 then gives "Medium when
   it would rate High or Critical in the role the component stands in for", and a deployed referee that stops
   accepting outputs would be Critical.
4. Critical: A5 is violated at a reachable state: "Conversely, the referee accepts every output that the settled
   state commits to, whenever its valid proof is presented. No party can make it stop accepting them." The settled
   state commits to output 0, a valid proof is presented by a connected player, and the model never accepts it.

Two readings. The preferred one is Critical. The model does not stop working (it keeps adopting connections and
reading lines). Its acceptance rules, a fixed one-shot audience, dropped responses from outside the audience and no
re-request, decide that a valid proof is never accepted. That is "what it accepts". The alternative is Medium (support).
Here the permanent `FOREVER` wait with no clock boundary is read as "only ... stalls the model", consistent with how
R1-A8-3 rated the model's `advance_time` barrier stall. The decisive fact is whether a freeze that the model's own
acceptance logic produces in its normal flow, with no party misbehaving, counts as "what it accepts" or as a stall.
The threat model does not say. Both readings give Medium or above.

### Possible solution and risks

Keep output acceptance open for every current and future player. For example, `wait_for_outputs` could re-issue
`prove_output` to `EVERYONE` in each later block (a `wait_until(get_time() + 1)` between rounds), so that late
connections join the audience and members can offer other outputs. Alternatively, the transport could accept
unsolicited `prove_output` responses from any player at any block, validated against the settled root. Another option
is to have the honest player offer each not-yet-accepted output in turn. That alone does not fix late presenters.
Risks: a referee that keeps advancing time never quiesces, so the demonstration needs its existing phase-closer stop
to end (the manual already says the script stops the server). The recipe's narration and transcript determinism checks
(the tournament is run twice and must narrate identically) must stay stable. The extra blocks change block numbers in
the story only after the tournament.

### Risk of not fixing it

The model is the manual's normative description of what the referee accepts. A deployed referee built to match it
would leave every output of an epoch except the first one each early player offers permanently unprovable. Anyone
could cause that by answering the first requests. Today the deployed Dave/rollups output validation accepts proofs at
any time, so the exposure is to implementations and reviews that follow the model, and to the demonstration's claim
that it models the PRT contracts. There is no mitigation outside the code other than not relying on the model for
output acceptance.
