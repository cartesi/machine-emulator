## R3-VARREFMODEL-2

**Title.** In the PRT referee model, any connection that reaches EOF without a `done` reply makes the referee process exit. One stray TCP close stops every match and all acceptance of outputs.

**Severity.** Medium (support rating of a referee-model crash that violates A8 and A5). Under a second reading it is Low; see Rating.

### Problem

The referee in `doc/recipes/prt.lua referee` runs over the `game-transport.lua` server. For every connection it
accepts, the server spawns a reader coroutine. When `receive_line` returns `nil` (the peer closed, or the socket
failed), that coroutine runs `assert(line, "unexpected connection loss: " .. tostring(err))`. The dispatcher turns any
error inside a coroutine into `error(debug.traceback(...))`. Its comment reads "Errors inside a coroutine are fatal:
the referee has no business surviving its own bugs". Nothing above `server:run` catches the error, so the referee
process exits. Other bad peer behavior, such as invalid JSON, a second announcement or a reply without an id, makes
the same coroutine call `close_connection` and carry on. Only an unannounced EOF is fatal.

So a peer's EOF, which is the peer's action and not a bug of the referee, stops everything the referee does.

- During a tournament, a claimant whose process dies or is killed after it posts its claim stops every other match,
  the honest claim's included. A8 forbids this: "Failing to process one match's data, for any reason, must not stop,
  delay or decide any other match."
- After the verdict, the referee waits forever in `wait_for_outputs` for output proofs. Any party that opens a TCP
  connection and closes it ends that wait, and no output of the settled state can be accepted any more. A5 forbids
  this: "the referee accepts every output that the settled state commits to, whenever its valid proof is presented.
  No party can make it stop accepting them."

The model stands in for the referee. A deployed referee with this behavior would let anyone with network access halt
every dispute and all output validation at no cost. A crashing or restarting honest player would do the same.

The manual (doc/README.md) describes the quitter's announced departure. In "Clocks and logical time" it documents
the stall of a player that "connects and never answers". It says nothing about a crash on an unannounced EOF. Only a
code comment on the client side (`run_client`) calls "an unannounced EOF or failed I/O ... a transport bug on either
side".

This is a different mechanism from R1-A8-3, and it needs a different fix. R1-A8-3 is the logical-time barrier, which
waits for a silent player that keeps its socket open. Here a closed socket is enough, and the referee exits within
a second. The R1-A8-3 entry mentions this crash as a problem its test does not cover.

### Component, role and area

The PRT referee model in `doc/recipes`: `doc/recipes/prt.lua` (referee) over `doc/recipes/game-transport.lua` (server
connection handling and coroutine dispatcher). AUDIT.md role: "The PRT referee model in `doc/recipes` | Referee
model". Area: connection lifecycle and error propagation in the referee's transport.

### Location

- `doc/recipes/game-transport.lua`, `server_meta.__index.adopt` (lines 548-605). The reader coroutine asserts at line
  567: `assert(line, "unexpected connection loss: " .. tostring(err))`. The writer coroutine has
  `assert(send_line(...))` at line 557, which fails in the same way when a write to a closed peer fails.
- `doc/recipes/game-transport.lua`, `receive_line` (lines 174-187). It returns `nil, err` on `closed` or any error
  other than `timeout`.
- `doc/recipes/game-transport.lua`, `dispatcher_meta.__index.step` (lines 121-142). It rethrows a coroutine error with
  `error(debug.traceback(turn[1], err))`.
- `doc/recipes/game-transport.lua`, `server_meta.__index.run` (lines 1182-1211) and `run_server` (1217-1222). Only
  `<close>` cleanup runs, and the error propagates out of `prtu.run_server` and `prt.lua` line 3313 (`run_role`).
- In the same family: `accept_connections` (lines 610-620, the assert at line 616), `assert(self.listener:accept())`. A failed accept, for example
  a connection reset before accept, would also be fatal. The test does not exercise this.
- For contrast, `close_connection` (lines 419-426) already exists and is used for every other bad-peer case.

### Evidence and test

`bugs/R3-VARREFMODEL-2/` contains the following.

- `test.sh` is adapted from `bugs/R1-A8-3/test.sh`. It runs two real referee tournaments with `prt.lua referee` on
  free loopback ports. Both use the harness's bare-metal `bugs/harness/work/configs/baremetal-template` and three
  inputs. Four player processes and the `phase_closer` join in the order that makes the referee pair
  `match 1 = P1 vs quitter` and `match 2 = honest vs "quitter 1"`.
  - Run "stray": P1 is a third `prt-dishonest.lua quitter`, which leaves with a `done` reply. The tournament settles,
    and the honest claim `0x84cc13c6...` wins. The test checks that the referee is still running 3 s after the
    verdict, while it waits for output proofs (control). It then opens one TCP connection to the referee port and
    closes it without sending a byte. It requires the referee to keep running for 15 s afterwards (A5).
  - Run "crash": P1 is `crashing-quitter.lua`. It requires match 2, which does not involve P1, to settle and the
    referee to stay up (A8).
- `crashing-quitter.lua` wraps `prt-dishonest.lua`'s quitter and posts the same kind of fabricated claim. At the
  first request after its claim, where the quitter would reply `done`, its process exits instead, so the kernel
  closes the socket with no reply.
- `README.md` describes the test.

The test exits 0 when both requirements hold, 1 when the referee dies of the connection loss or match 2 does not
settle, and 2 on setup errors. It starts no chain and kills every process it starts. No wall-clock threshold decides
the result: the referee exits within a second of the EOF, and the waits only bound the observation.

Run with `bugs/run.sh R3-VARREFMODEL-2` (about 15 s). The reviewer re-ran it twice on audit/prt2, and both runs
exited 1. The output of the first run, with the referee traceback lines trimmed:

```
stray: tournament:
  Round 1, match 1, at the mcycle level: claim 0x87f38778... against claim 0x1a22b0c7....
  Round 1, match 2, at the mcycle level: claim 0x84cc13c6... against claim 0x0e6cdf5f....
  Match 1: no claim survives.
  Match 2: claim 0x84cc13c6... wins.
stray: Tournament winner is claim 0x84cc13c6....
stray: referee alive 3s after the verdict, waiting for output proofs (1 connections open)
stray: a TCP client connected and closed without sending anything
stray: referee EXITED after the stray connection closed: unexpected connection loss: closed
FAIL (A5): one stray connection made the referee stop accepting outputs of the settled state
crash: claims:
  Claim 0x037210df..., with final state 0x58904e74..., joined (posted by crasher).
  Claim 0x1a22b0c7..., with final state 0xdd2e60cd..., joined (posted by quitter).
  Claim 0x84cc13c6..., with final state 0xbab85ef1..., joined (posted by honest).
  Claim 0x0e6cdf5f..., with final state 0x2743a118..., joined (posted by quitter 1).
crash: tournament:
  Round 1, match 1, at the mcycle level: claim 0x037210df... against claim 0x1a22b0c7....
  Round 1, match 2, at the mcycle level: claim 0x84cc13c6... against claim 0x0e6cdf5f....
crash: crasher: process dies at reveal_bisection (no reply, socket closed by exit)
crash: referee EXITED: unexpected connection loss: closed
FAIL (A8): match 2 (honest vs quitter 1) did not settle because the claimant of match 1 crashed
run.sh: R3-VARREFMODEL-2: exit 1 (bug present)
```

As a check that the test fails only for this defect, the reviewer ran it against an untracked copy of the recipes
in scratch space, with the same `test.sh`, `RECIPES_DIR` and `LUA_PATH_5_4` pointed at the copy. In the copy, line
567 was replaced by `if not line then close_connection(self, connection) return end`. The test then exited 0. The
referee was still running 15 s after the stray connection. In the crash run, `Match 1: no claim survives.` and
`Match 2: claim 0x84cc13c6... wins.` were printed, followed by `PASS`. The reviewer did not change the test. Found,
proved and reviewed on Opus 5.5, with no fallback.

### Trigger and reachability

Two kinds of party trigger it.

- Any party that can open a TCP connection to the referee and close it. It needs no claim, no role announcement and
  no bytes. This works at any time, including after the verdict, while the referee accepts outputs.
- A claimant whose player process exits, crashes or is killed before it replies `done`. Threat model section 4 lists
  "dishonest claimants (any number, any logs, any proofs, any timing)" as untrusted. Section 7 lets the adversary
  "abandon or defend [claims] at will". An honest player that crashes and restarts, as R4 expects ("After a stop, it
  restarts ... and keeps defending its claim"), also closes its old connection without `done`, and that kills the
  referee.

No property of the template or the inputs is involved. Any epoch reaches the state, with any valid template.

### Rating

1. Out of scope: no. The exclusion "Defects that need the deployment to violate one of A1 to A8" makes an exception
   for the case where "an implementation of the referee model is what violates it (section 3)", and that is this
   case. The trigger is a peer closing a TCP connection to the referee. It is not a call to the machine API by an
   untrusted party ("the C, Lua and JSON-RPC interface to a machine"). It is not a snapshot, an O1/O2 situation, a
   host fault, an application stall or a reorganization. `prt-dishonest.lua` and the test harnesses are out of scope
   as components, but the defect is in the referee's transport, not in them.
2. Role: the component is "The PRT referee model in `doc/recipes` | Referee model" (AUDIT.md). Section 3, "Referee
   model": "A defect that only changes how long a claim may take to respond, or only crashes or stalls the model,
   even when that stops other matches (A8), is rated as support." This clause covers this component and this defect
   exactly. The defect only crashes the model. It changes nothing the model accepts or derives. So it is rated as
   support. Section 3, "Support": "A defect that only a support component shows is Medium when it would rate High or
   Critical in the role the component stands in for". The model stands in for the deployed referee. Section 8 step 2:
   "A defect that only a support component shows is never above Medium."
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." Section 3
   rates it Medium if a deployed referee with the defect would be High or Critical. It would be Critical (step 4), so
   this case fits and the class is Medium.
4. Critical, in the stood-in role (used only to apply the support rule): a deployed referee that halts when any peer
   disconnects violates A8 ("Failing to process one match's data, for any reason, must not stop, delay or decide any
   other match") and A5 ("No party can make it stop accepting them") at a reachable state. The state is reached from
   any valid template with any inputs. The honest claim could never win, and no output could be validated.

Second reading (Low): the `run_client` comment calls an unannounced EOF "a transport bug on either side". Read
together with the dispatcher's "Errors inside a coroutine are fatal" policy, it suggests the crash is a deliberate
fail-stop design of a demonstration that trusts its peers. Under that reading this is a documented limitation that
violates no rule, and it is Low. This reviewer judges the Medium reading better supported, for three reasons.
- The comment is in the code, not in the manual, which is the normative reference for the referee model.
- Section 3 covers even the manual: if "the manual's model itself violates one of A1 to A8; then the manual is the
  defect, rated as a defect of the referee model", and the support clause then rates that crash Medium.
- The same reader coroutine already closes the connection, and does not crash, on every other peer misbehavior. A
  peer's EOF is not "the referee['s] own bug".

The fact that would decide: whether a fail-stop transport that a code comment documents counts as a defect of the
referee model. The threat model rates crashes of the model "as support" without excepting documented ones.

### Possible solution and risks

In the reader coroutine of `adopt`, treat EOF or a receive error like any other forfeit:
`if not line then close_connection(self, connection) return end`. In the writer coroutine, do the same when
`send_line` fails, and in `accept_connections`, skip a failed `accept` instead of asserting. `close_connection` already
calls `forget_connection`, which drops the connection from pending requests and barriers. Matches then go on by
timeout or elimination, as in the quitter case. This is what the reviewer's patched copy shows.

Risks:
- `close_connection` asserts that the phase closer is not lost before admission closes ("the phase closer went
  away"). An EOF from the phase-closer connection would still be fatal unless that case is handled too.
- A writer coroutine parked on a dead connection must not be resumed against the closed socket.
- Transcripts that the recipe compares between its two runs must not depend on when a connection drops.
- The client-side comment in `run_client` should be updated to match.

### Risk of not fixing it

The referee model is a demonstration, and no deployment runs it. Still, in any run of it, anyone who can reach its
port can end the tournament and all output acceptance with a single connect and close. Any player crash does the
same. A deployed referee that copied this transport design would let any party halt every dispute and the
validation of every output, which breaks A5 and A8. The model would then teach a referee design that the threat
model forbids. Outside the code, the only mitigation is to firewall the referee port to trusted players and to
never restart a player, which contradicts the permissionless model.
