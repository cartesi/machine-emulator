# R1-A8-3: one silent claimant freezes logical time in the referee model, stopping every other match

Component: referee model, `doc/recipes/prt.lua referee` over `doc/recipes/game-transport.lua`
(`server_meta.__index.step_time`: every block is a barrier over an `advance_time` notification sent to
every connected player; `adopt()` keeps one outstanding event per connection, so a connection stuck on
a request also never answers the `advance_time` queued behind it).

## What is asserted

Two real tournaments over the same epoch (the harness's bare-metal `baremetal-template`, three inputs),
each with four player processes joined in the same order, so the referee pairs
`match 1 = P1 vs quitter` and `match 2 = honest vs "quitter 1"`:

* control: P1 is a third `prt-dishonest.lua quitter` ("quitter 2"), which leaves after posting its claim;
* silent: P1 is `silent-quitter.lua`, the same fabricated quitter claim, but after posting it the player
  keeps its connection open and never answers again (it stops at its first match request,
  `reveal_bisection` of match 1).

Match 2 does not involve P1. The test requires that it settles in the silent run as it does in the control
(`Match 2: ...` in the referee's `tournament` narration). The bound for the silent run is 10x the control's
settle time, at least 60 s. The logical block the honest player last saw is printed as count-based
evidence: the control run reaches block 12 and settles, while the silent run stays at block 3. At block 3
the honest player has received its own `reveal_bisection` for match 2, and its answer can never be
accepted because block 4 never comes.

Requirement (THREAT_MODEL.md, section 5):

> **A8. Isolated matches.** Failing to process one match's data, for any reason, must not stop, delay or
> decide any other match.

Section 3 ("Referee model") rates a defect that "only crashes or stalls the model, even when that stops
other matches (A8)" as support. doc/README.md ("Clocks and logical time") describes the behavior: "A
player that connects and never answers therefore stalls the demonstration". It is not in the manual's
closing list of the model's simplifications.

## Run

```sh
bugs/run.sh R1-A8-3          # about 70 s; KEEP=1 keeps the run directories (printed path)
```

Needs the in-tree emulator and `bugs/harness/work/configs/baremetal-template`. It uses free loopback ports,
starts no chain, and kills every process it starts.

Exit: 0 when match 2 settles despite the silent claimant (fixed), 1 when it does not (bug present), and 2 on
setup errors (the control did not settle, a player did not connect, the referee died).

## Expected output on audit/prt2

```
control: ... Match 1: no claim survives. / Match 2: claim 0x84cc13c6... wins.
control: Tournament winner is claim 0x84cc13c6....; match 2 settled after 1s; honest saw logical block 12
silent: tournament after 60s: only the two "Round 1" lines
silent: silent: stops answering at reveal_bisection, connection kept open; honest saw logical block 3
FAIL (A8): match 2 (honest vs quitter 1) did not settle within 60s (control: 1s)
run.sh: R1-A8-3: exit 1 (bug present)
```

Files: `test.sh` (orchestration, like `doc/recipes/prt-repeat-test.sh`) and `silent-quitter.lua` (wraps
`prt-dishonest.lua`'s quitter and blocks instead of leaving).

Side observation, not part of this test: a TCP connection to the referee that closes before announcing a
role crashes the referee (`game-transport.lua:567: unexpected connection loss: closed`). An early version
of this test probed the port with a plain connect and hit it.
