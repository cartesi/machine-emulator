# R3-VARREFMODEL-1: any connection can be the referee model's phase closer

Component: PRT referee model, `doc/recipes/prt.lua referee` over `doc/recipes/game-transport.lua`
(`announce` / `announce_phase_closer`: the first connection that sends `{"role":"phase_closer"}` becomes
the closer, and a later real closer is refused; `deliver`: its `done` closes admission through
`close_phase`, which fixes `phase.players = get_players()`, the only connections that ever get
`commit_mcycle_claim`; any connection that sends `{"role":"phase_closer","command":"stop"}` sets
`self.stopping`, and `server:run` then closes the referee). The transport says so itself: "The phase closer
is trusted orchestration. Its announced role is not authenticated." The manual never mentions a phase
closer.

## What is asserted

`closer-client.lua` is an arbitrary TCP client. It sends exactly the lines that
`prt.lua phase_closer <address> [stop]` sends; there is no secret to hold. Three runs over the harness's
bare-metal `baremetal-template` with one input:

* **control**: referee; `prt-dishonest.lua quitter` joins (fabricated claim); `prt.lua honest` joins;
  the orchestration's `prt.lua phase_closer` closes admission. The honest claim must win (setup check,
  exit 2 otherwise).
* **stop**: the control referee has settled and waits for output proofs (`wait_for_outputs`, forever).
  The arbitrary client sends the phase-closer `stop` announcement. Required: the referee does not end
  (checked for 20 s; on `audit/prt2` it exits with status 0 at once).
* **attack**: as control, but right after the quitter joins, the arbitrary client announces the
  phase-closer role and answers `close_phase`. Then the honest player joins and the orchestration's phase
  closer runs as usual. Required: the winner's computation hash equals the control winner's (the honest
  claim). On `audit/prt2` the quitter's fabricated claim wins. The honest player never receives
  `commit_mcycle_claim` (0 in its wire trace, against 1 in the control run), and the referee refuses the
  real phase closer.

Requirements:

> (section 1) no adversary can make a correctly designed application settle a state that differs from
> the one the state transition function defines

> **A7.** ... No rule of the referee may make the honest claim lose by timeout while it acts within its own
> clock.

> **A5.** ... Conversely, the referee accepts every output that the settled state commits to, whenever its
> valid proof is presented. No party can make it stop accepting them.

Section 3, referee model: "A defect in what it accepts or derives is rated as if a deployed referee had it"
and "A defect that ... only crashes or stalls the model, even when that stops other matches (A8), is rated
as support". doc/README.md: "The referee requests and the players' responses that go through the wire
represent blockchain events and transactions, respectively" and "The mcycle tournament opens to every
player subscribed to the epoch's initial state hash". Its list of simplifications says "The referee is
one trusted process" and "The model gathers a tournament's claims first", but does not mention the
phase closer. Whether a phase-closer announcement counts as an untrusted party's transaction is left to
the reviewer. The test only shows what the model accepts from any connection.

## Run

```sh
bugs/run.sh R3-VARREFMODEL-1      # about 15 s; KEEP=1 keeps the run directories (path printed)
```

Needs the in-tree emulator and `bugs/harness/work/configs/baremetal-template`. It uses free loopback ports,
starts no chain, and kills every process it starts. The connection checks look up each player's own
socket in `/proc`. They do not count connections to the port, because the quitter leaves after
posting its claim.

Exit status: 0 if both requirements hold (fixed), 1 if either is violated (bug present), 2 on setup
errors. A fix that authenticates the closer may change how the orchestration's closer is invoked. The
test's `prt.lua phase_closer "$ADDR"` lines (control and attack runs) would then need the same change.
A fix that closes admission by logical time instead needs no closer, and its failure is harmless.

## Expected output on audit/prt2

```
control: claims:
  Claim 0x1a22b0c7..., with final state 0xdd2e60cd..., joined (posted by quitter).
  Claim 0x0178c769..., with final state 0xcbc647b5..., joined (posted by honest).
control: winner computation hash 0x0178c769...; honest got commit_mcycle_claim 1 time(s)
stop: arbitrary client announced {"role":"phase_closer","command":"stop"}: answered close_phase
stop: the referee ended (exit status 0) while waiting for output proofs; ...
attack: arbitrary client announced {"role":"phase_closer"} before the honest player joined: answered close_phase
attack: claims:
  Claim 0x1a22b0c7..., with final state 0xdd2e60cd..., joined (posted by quitter).
attack: winner computation hash 0x1a22b0c7...; honest got commit_mcycle_claim 0 time(s)
attack: the orchestration's phase closer, run after the honest player joined: lua5.4: .../game-transport.lua:286: closed
FAIL (section 1 goal, A7): an unauthenticated connection closed claim admission before the honest
  player joined; the honest claim never entered and the winner is 0x1a22b0c7... (posted by quitter)
  instead of the honest claim 0x0178c769....
FAIL (A5): an unauthenticated connection stopped the settled referee; it no longer accepts output proofs.
run.sh: R3-VARREFMODEL-1: exit 1 (bug present)
```

Files: `test.sh` (orchestration), `closer-client.lua` (the arbitrary client).
