# R3-VARREFMODEL-2: one connection lost without a "done" reply makes the referee model exit

Component: referee model, `doc/recipes/prt.lua referee` over `doc/recipes/game-transport.lua`. Every
connection the referee accepts gets a reader coroutine (`server_meta.__index.adopt`) that does
`assert(line, "unexpected connection loss: " .. tostring(err))`; `dispatcher_meta.__index.step` turns an
error in any coroutine into `error(...)`, which nothing catches, so the referee process exits. Any peer
that closes its socket without first replying `done` (a stray client, a claimant whose process crashes or
is killed) stops the whole referee: every match and the outputs phase.

## What is asserted

Two real tournaments over the same epoch (the harness's bare-metal `baremetal-template`, three inputs),
four players joined in the order of `bugs/R1-A8-3`, so the referee pairs
`match 1 = P1 vs quitter` and `match 2 = honest vs "quitter 1"`.

1. **stray** (P1 = a third `prt-dishonest.lua quitter`, which leaves with a `done` reply): the tournament
   settles (`Match 2: claim 0x84cc13c6... wins`, winner = honest). The referee is then in
   `wait_for_outputs`, which waits forever for output proofs; the test checks it is still running 3 s
   later (control), then opens one TCP connection to the referee port and closes it without sending a
   byte. Required: the referee is still running 15 s later.
   > **A5.** ... the referee accepts every output that the settled state commits to, whenever its valid
   > proof is presented. No party can make it stop accepting them.
2. **crash** (P1 = `crashing-quitter.lua`: the quitter's claim, but at the first request after its claim,
   where the quitter would reply `done`, its process exits): required: match 2, which does not involve
   P1, settles exactly as in the stray run, and the referee keeps running.
   > **A8. Isolated matches.** Failing to process one match's data, for any reason, must not stop, delay
   > or decide any other match.

Section 3 ("Referee model") rates a defect that "only crashes or stalls the model, even when that stops
other matches (A8)" as support. The manual (doc/README.md) describes the quitter's announced departure
and the stall of a player that "connects and never answers" (bugs/R1-A8-3), but not a crash on an
unannounced EOF; only a code comment in `game-transport.lua` (`run_client`) calls an unannounced EOF "a
transport bug on either side".

No wall-clock threshold decides the result: in both cases the referee process exits within a second
of the connection loss with `unexpected connection loss: closed`; the 15 s / 120 s waits only bound the
observation. As a check of the test (not tracked), a copy of the recipes whose reader coroutine closes the
connection on EOF instead of asserting (`if not line then close_connection(self, connection) return end`)
makes the test exit 0: the referee survives the stray connection and, in the crash run,
`Match 1: no claim survives.` / `Match 2: claim 0x84cc13c6... wins.`

## Run

```sh
bugs/run.sh R3-VARREFMODEL-2     # about 15 s; KEEP=1 keeps the run directories (printed path)
```

Needs the in-tree emulator and `bugs/harness/work/configs/baremetal-template`. It uses free loopback
ports, starts no chain, and kills every process it starts. Exit 0: both requirements hold (fixed); 1: the
referee died of a connection loss, or match 2 did not settle (bug present); 2: setup error (no winner in
the stray run, a player did not connect, the crashing claimant was never asked anything).

## Expected output on audit/prt2

```
stray: Tournament winner is claim 0x84cc13c6....
stray: referee alive 3s after the verdict, waiting for output proofs (1 connections open)
stray: a TCP client connected and closed without sending anything
stray: referee EXITED after the stray connection closed: unexpected connection loss: closed
FAIL (A5): one stray connection made the referee stop accepting outputs of the settled state
crash: tournament:
  Round 1, match 1, at the mcycle level: claim 0x037210df... against claim 0x1a22b0c7....
  Round 1, match 2, at the mcycle level: claim 0x84cc13c6... against claim 0x0e6cdf5f....
crash: crasher: process dies at reveal_bisection (no reply, socket closed by exit)
crash: referee EXITED: unexpected connection loss: closed
FAIL (A8): match 2 (honest vs quitter 1) did not settle because the claimant of match 1 crashed
run.sh: R3-VARREFMODEL-2: exit 1 (bug present)
```

Files: `test.sh` (orchestration, adapted from `bugs/R1-A8-3/test.sh`) and `crashing-quitter.lua` (wraps
`prt-dishonest.lua`'s quitter and exits instead of replying `done`).
