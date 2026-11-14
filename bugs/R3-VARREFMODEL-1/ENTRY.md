## R3-VARREFMODEL-1

**Title.** The PRT referee model takes the phase-closer role from any connection, so any party can close claim admission before the honest player joins (a fabricated claim then settles), or stop the referee at any time.

**Severity.** Critical (preferred reading: the close effect is rated "as if a deployed referee had it", per section 3). The stop effect alone is support Medium. Low under the alternative reading in which the phase closer's announcement is a trusted channel of the referee process itself.

The first reviewer refuted this candidate as Low. It read the closer as "trusted orchestration" with no deployed counterpart, and so outside section 3's "as if a deployed referee had it". A second-opinion reviewer overturned that. Section 3 says "A defect in what it accepts or derives is rated as if a deployed referee had it", with no limit to channels that have a deployed counterpart. The closer's trust came from a code comment (`game-transport.lua`: "The phase closer is trusted orchestration. Its announced role is not authenticated."), not from section 4 or the manual. The manual's simplification "The referee is one trusted process" covers the referee, not a separate connection. Section 5 makes that simplification non-normative. The closer's `done` also answers a referee request (`close_phase`). The manual says such wire responses "represent blockchain events and transactions" (verification-game section; "The referee uses the verification game's transport").

### Problem

In the PRT referee model, claimants are admitted through a wall-clock admission phase. `close_phase` fixes
`phase.players = self:get_players()` when the phase closer answers `close_phase`. Only those connections are
subscribed to the epoch's initial state hash, and only they ever receive `commit_mcycle_claim`
(`prt.lua open_mcycle_tournament`). A player that connects later is never subscribed and cannot post a claim.

The server decides which connection is the phase closer from that connection's first line. The first connection that
sends `{"role":"phase_closer"}` becomes `self.phase_closer`. When it answers `done`, admission closes at once, and the
real closer is refused later (`if self.phase_closer then close_connection`). Any connection that sends
`{"role":"phase_closer","command":"stop"}` at any time sets `self.stopping`. `server:run` then closes the referee
coroutine and ends the referee, even mid-match or while it waits for output proofs. There is no secret and no
authentication.

An adversary that closes admission before the honest player connects keeps the honest claim out of the tournament.
The test shows the result: the quitter's fabricated claim wins. A deployed referee with this behavior would let any
party settle a state that the state transition function does not define, which breaks the goal of section 1. The
manual's model says "The mcycle tournament opens to every player subscribed to the epoch's initial state hash" and
never mentions a phase closer. Dave has no such gate: joins stay open until the tournament's clock-based closure.

### Component, role and area

The PRT referee model in `doc/recipes` (`prt.lua referee` over `game-transport.lua`). AUDIT.md role: "The PRT referee
model in `doc/recipes` | Referee model". Area: claim admission and server lifecycle (the phase-closer role).

### Location

- `doc/recipes/game-transport.lua`: `announce` and `announce_phase_closer` (the role is taken from the first line,
  unauthenticated); `deliver` (`done` closes the phase or sets `self.stopping`); `close_phase` (fixes
  `phase.players`); `server_meta.__index.run` (`self.stopping` leads to `close_referee`); the comment "The phase
  closer is trusted orchestration. Its announced role is not authenticated."
- `doc/recipes/prt.lua`: `new_referee` (admission, then `run_epoch`), `open_mcycle_tournament` (`commit_mcycle_claim`
  goes only to subscribed connections), `wait_for_outputs`.

### Evidence and test

`bugs/R3-VARREFMODEL-1/` holds `test.sh` (the orchestration) and `closer-client.lua`, an arbitrary TCP client that
sends the same lines as `prt.lua phase_closer <address> [stop]`. The runs use the harness's bare-metal
`baremetal-template` with one input, free loopback ports, and no chain:

- control: a quitter joins, then the honest player, then the orchestration's closer closes admission. The honest
  claim wins (setup check).
- stop: the settled control referee waits for output proofs, and the arbitrary client sends the `stop`
  announcement. Required: the referee does not end.
- attack: after the quitter joins, the arbitrary client announces the closer role and answers `close_phase`. Then
  the honest player joins. Required: the honest claim still enters and wins.

Run with `bugs/run.sh R3-VARREFMODEL-1` (about 15 s). Output on audit/prt2 (second-opinion re-run, exit 1):

```
control: winner computation hash 0x0178c769...; honest got commit_mcycle_claim 1 time(s)
stop: the referee ended (exit status 0) while waiting for output proofs
attack: claims:
  Claim 0x1a22b0c7..., with final state 0xdd2e60cd..., joined (posted by quitter).
attack: winner computation hash 0x1a22b0c7...; honest got commit_mcycle_claim 0 time(s)
FAIL (section 1 goal, A7): an unauthenticated connection closed claim admission before the honest player joined
FAIL (A5): an unauthenticated connection stopped the settled referee; it no longer accepts output proofs.
run.sh: R3-VARREFMODEL-1: exit 1 (bug present)
```

Found by the round-3 VARREFMODEL hunter, proved by the prover, refuted by the first reviewer, and overturned by a
second-opinion reviewer (Opus 5.5). No fallback model was used.

### Trigger and reachability

Any party that can open a TCP connection to the referee, such as a dishonest claimant (section 4: "dishonest
claimants (any number, any logs, any proofs, any timing)"). To close admission, it connects before the honest player
and sends `{"role":"phase_closer"}`, then `{"value":"done"}`. That is a race, which section 7 grants ("Race and
reorder transactions within the chain's rules"). To stop the referee, it sends
`{"role":"phase_closer","command":"stop"}`, then `done`, at any time, with no race. No machine state is involved.

### Rating

1. Out of scope: no. The trigger is not a machine API call, so "Defects that need an untrusted party to call the
   machine API directly" does not apply. The A1-A8 exclusion does not apply either: it holds "unless an implementation
   of the referee model is what violates it (section 3)". No exclusion makes the referee model's peers trusted.
   Section 4's trusted column lists no referee orchestrator.
2. Role: referee model (AUDIT.md table). Section 3: "A defect in what it accepts or derives is rated as if a deployed
   referee had it." The model accepts an unauthenticated close, and that close decides which claims can enter, which
   is part of what the model derives. Section 3: "A defect that ... only crashes or stalls the model, even when that
   stops other matches (A8), is rated as support." That clause covers the stop effect alone.
3. High and Medium cases: for the close effect, none fits. For the stop effect, support Medium: "A defect that only
   a support component shows is Medium when it would rate High or Critical in the role the component stands in for".
   A deployed referee that any party could stop would break A5 ("No party can make it stop accepting them").
4. Critical: the close effect, rated as a deployed referee, breaks the goal of section 1 ("no adversary can make a
   correctly designed application settle a state that differs from the one the state transition function
   defines"). It also violates A7: "No rule of the referee may make the honest claim lose by timeout while it acts
   within its own clock". The honest claim is shut out although it acts in time.

Alternative reading: Low. This holds if the phase closer counts as part of the manual's "The referee is one trusted
process", so that an announcement from another connection is the referee operator's own control and not an untrusted
transaction. Two facts would decide it. First, whether the maintainers mean the closer channel to be trusted. If so,
the model should authenticate it or bind it to the referee process, and the manual should say so. Second, whether the
manual's simplification "gathers a tournament's claims first" was meant to include an externally closed admission
phase.

### Possible solution and risks

Close initial admission by logical time, as tournament claim collection already does ("Tournament claim collection
closes at a supplied logical block"). The other option is to authenticate the closer: a secret passed to the referee
at launch, or a closer that only the referee process can reach. Remove the network `stop` command, or authenticate it
the same way. Risks: the deterministic narration relies on the fixed set of admitted players. A logical-time admission
must keep the transcript reproducible ("The recipe runs the tournament twice and requires identical narration"). The
recipe tests that drive `phase_closer` (`prt-test.lua`, `prt-deadline-test.lua`, `game-transport-test.lua`) need
updating.

### Risk of not fixing it

Any code derived from the model inherits a referee whose claim set and lifetime any peer controls. Anyone who can
reach the referee's port can keep the honest claim out and make a fabricated claim win, or stop all matches and
output acceptance. Mitigation outside the code: run the model only on a host where every peer is trusted. That
abandons the model's adversarial setting.
