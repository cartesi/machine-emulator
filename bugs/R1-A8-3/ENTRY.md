## R1-A8-3

**Title.** In the PRT referee model, logical time advances only once every connected player answers `advance_time`, so one claimant that keeps its connection open and stops answering freezes every other match.

**Severity.** Medium (support rating of a referee-model stall that violates A8). Under a second reading it is Low; see Rating.

### Problem

The referee in `doc/recipes/prt.lua referee` runs in logical blocks over the `game-transport.lua` server. Before it
moves to the next block, it sends an `advance_time` notification to every connected player. It then waits, with no
bound, until each one has replied (`step_time` calls `clock:barrier_ready(self.batch)`). Each connection also has at
most one outstanding event (`send_next_event` sends nothing while `connection.current_event` is set). A player that
stops answering a request therefore never receives, and never answers, the `advance_time` queued behind it. A player
that answers nothing at all has the same effect. In both cases no block after the current one ever comes.

Match deadlines are counted in these blocks. In a match whose on-turn claim has walked away, the other claim wins
only when its timeout-win response is accepted in a later block. When time stops, that match never settles, and
neither does the tournament. So one claimant that stops processing its own match stops every other match, including
the honest claim's. A8 forbids this: "Failing to process one match's data, for any reason, must not stop, delay or
decide any other match." The model stands in for the referee. A deployed referee with this behavior would let any
claimant keep the honest claim from ever winning, with no cost beyond an open connection.

The manual documents the behavior ("A player that connects and never answers therefore stalls the demonstration,
where a blockchain would let its deadline pass", doc/README.md, "Clocks and logical time"). The closing paragraph that
lists the model's simplifications of the PRT contracts does not include it.

### Component, role and area

The PRT referee model in `doc/recipes`: `doc/recipes/prt.lua` (referee) over `doc/recipes/game-transport.lua` (server
block clock) and `doc/recipes/game-clock.lua`. AUDIT.md role: "The PRT referee model in `doc/recipes` | Referee model".
Area: logical-time advancement and per-connection event delivery.

### Location

- `doc/recipes/game-transport.lua`, `server_meta.__index.step_time` (around lines 1011-1137). After a batch of
  `advance_time` notifications, `if not self.clock:barrier_ready(self.batch) then return end`. A new block is opened
  by `self.batch = { entry }`, with `entry.pending[connection] = true` for every player in `self:get_players()`.
- `doc/recipes/game-clock.lua`, `clock.__index.barrier_ready`, which is false while any entry has a pending
  connection. There is no timeout.
- `doc/recipes/game-transport.lua`, `send_next_event` / `send_event` (lines 438-454). There is one outstanding event
  per connection, so a connection stuck on a request also holds back its `advance_time`. In the receive loop of
  `adopt` (around lines 564-603), a connection's pending entries are dropped only when it closes or sends a malformed
  reply.

### Evidence and test

`bugs/R1-A8-3/` contains the following.

- `test.sh` runs two real referee tournaments with `prt.lua referee` on loopback ports. It uses the harness's
  bare-metal `baremetal-template` (`emit-output.bin` at its first accepted yield) and three inputs. Each tournament has
  four player processes and the `phase_closer`, joined in an order that makes the referee pair them as
  `match 1 = P1 vs quitter` and `match 2 = honest vs "quitter 1"`. In the control run, P1 is a third
  `prt-dishonest.lua quitter` ("quitter 2"), which leaves after posting its claim. In the silent run, P1 is
  `silent-quitter.lua`. The test requires that match 2, which does not involve P1, settles in the silent run as it
  does in the control run. The bound is 10 times the control's settle time, and at least 60 s. The test prints the
  highest logical block that the honest player saw, as count-based evidence. It starts no chain, and it kills every
  process it starts.
- `silent-quitter.lua` wraps `prt-dishonest.lua`'s quitter. It posts the same kind of fabricated claim, then keeps
  its socket open and never answers the next request (it blocks at `reveal_bisection` of match 1).
- `README.md` describes the test.

Run with `bugs/run.sh R1-A8-3` (about 70 s). The reviewer re-ran it twice on audit/prt2. Both runs exited 1 with the
same output, ending with these lines:

```
control: Tournament winner is claim 0x84cc13c6....; match 2 settled after 1s; honest saw logical block 12
silent: tournament after 60s:
  Round 1, match 1, at the mcycle level: claim 0x6776c3d1... against claim 0x1a22b0c7....
  Round 1, match 2, at the mcycle level: claim 0x84cc13c6... against claim 0x0e6cdf5f....
silent: silent: stops answering at reveal_bisection, connection kept open; honest saw logical block 3
FAIL (A8): match 2 (honest vs quitter 1) did not settle within 60s (control: 1s)
run.sh: R1-A8-3: exit 1 (bug present)
```

In the control run, match 2 settles within about 1 s, at logical block 12, and the honest claim wins the tournament.
In the silent run, logical time stays at block 3. That is the block in which the honest player received its own
`reveal_bisection` for match 2. Its answer could be accepted only in block 4, which never comes. The test exits 0 once
match 2 settles despite the silent claimant. It exits 2 on setup errors (the control does not settle, a player does
not connect, or the referee dies). No process was left behind. Found, proved and reviewed on Opus 5.5, with no
fallback.

The prover saw another problem that this test does not cover. A TCP connection that closes before announcing a role
crashes the referee (`game-transport.lua:567: unexpected connection loss: closed`).

### Trigger and reachability

Any party that can connect to the referee as a player triggers it. The test uses a claimant that posts a valid join
(a fabricated claim, as the quitter does) and then keeps the connection open while answering nothing more. Threat
model section 4 lists "dishonest claimants (any number, any logs, any proofs, any timing)" as untrusted, and section 7
lets the adversary "abandon or defend [claims] at will". Code reading suggests that a player with no claim, which
answers no `advance_time`, has the same effect, because the barrier covers every connected player. The test does not
exercise that case. No property of the template or the inputs is involved. Any epoch reaches the state once a match
needs a later block.

### Rating

1. Out of scope: no. The exclusion "Defects that need the deployment to violate one of A1 to A8" makes an exception
   for the case where "an implementation of the referee model is what violates it (section 3)", and that is this
   case. The trigger is a dishonest claimant's timing. It is not a snapshot, an O1/O2 situation, a host fault, an
   application stall or a direct API call by an untrusted party. The test harnesses (`*-test.sh`) and
   `prt-dishonest.lua` are out of scope as components, but the defect is in the referee and transport, not in them.
2. Role: the AUDIT.md table gives "The PRT referee model in `doc/recipes` | Referee model". Section 3, "Referee model",
   says: "A defect that only changes how long a claim may take to respond, or only crashes or stalls the model, even
   when that stops other matches (A8), is rated as support." That clause covers this component and this symptom
   exactly: a stall that stops other matches. The support rule then applies: "A defect that only a support component
   shows is Medium when it would rate High or Critical in the role the component stands in for." The referee model
   "stands in for that normative model", and "A defect in what it accepts or derives is rated as if a deployed referee
   had it." A deployed referee in which one claimant's silence stops every other match would violate A8 at a
   reachable state, which is Critical by step 4. The deployed Dave contracts do not share the defect, since block time
   advances on-chain.
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." This case
   applies, so the class is Medium. Section 8 step 2 also caps it: "A defect that only a support component shows is
   never above Medium."
4. Critical: not reached. For the record, the obligation violated is A8: "Failing to process one match's data, for
   any reason, must not stop, delay or decide any other match." In the stood-in role, A7 would also fail: "No rule of
   the referee may make the honest claim lose by timeout while it acts within its own clock." The honest claim cannot
   win at all.

Second reading (Low). Two facts decide between the readings.

- (a) Section 5 says that "The simplifications that the manual lists for it are not normative, and neither are its
  clock values." The stall is documented in the manual's clock section, which contrasts it with "a blockchain [that]
  would let its deadline pass". If that sentence counts as a listed simplification, or the barrier counts as part of
  the non-normative clock, then the model follows a non-normative simplification. It is then not a defect under
  section 3, which leaves Low or no defect. The reviewer judges this reading weaker. The manual's explicit list ("The
  model simplifies the PRT contracts in a few ways ...") does not include the stall. "Clock values" reads as the
  numeric allowances, not as whether logical time can advance at all.
- (b) If "the role the component stands in for" is read as the referee model itself, the referee-model clause sends
  stalls back to support, and the rule "Any other support defect is Low" applies. The reviewer judges this reading
  circular. It would also make the words "rated as support" in place of "Low" pointless.

If the manual's description is taken as the normative model, then "the manual's model itself violates one of A1 to
A8", and section 3 makes the manual the defect, "rated as a defect of the referee model". That gives the same support
rating, Medium.

### Possible solution and risks

Option 1: let logical time advance without waiting on players that do not answer. Two ways to do this:

- Bound each `advance_time` barrier with a wall-clock timeout, and drop the players that miss it from that barrier,
  or treat them as departed.
- Keep `advance_time` out of the one-outstanding-event queue, so that a connection stuck on a request does not hold
  back the clock. Then close connections that leave a request unanswered past a wall-clock bound.

Either way, only a timeout-win or elimination response, sent by any player, settles a match, as the model already
requires.

Risks of option 1:

- The recipe runs the tournament twice and requires identical narration. Wall-clock timeouts make the transcript
  depend on scheduling unless the bound is generous and dropping a player is narrated deterministically.
- A slow honest player (a long uarch-level computation or proof) must never be dropped. A drop would itself make the
  honest claim lose by timeout (A7). The bound must therefore exceed the worst-case response time that R12 implies,
  or apply only to the barrier and not to the match clocks.

Option 2: state in the manual's list of simplifications that a silent connected player stalls the model, which makes
the behavior non-normative. This makes it a documented limitation of the demonstration and leaves the code unchanged.

Separately, make the receive loop of an unannounced connection close the connection rather than `assert`, so that an
early disconnect does not crash the referee.

### Risk of not fixing it

No production deployment runs the referee model. The deployed referee (Dave) advances by block time and does not
share the stall. The risk is that the demonstration and its tests misrepresent A8. Any participant that connects to
a model referee can freeze every match and keep the honest claim from winning, which a deployed referee must never
allow. Anyone who builds an off-chain referee or a test network on this transport inherits the freeze. Outside the
code, the mitigation is to run the model only with trusted players and an external wall-clock watchdog.
