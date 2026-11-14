# R1-A7-3: a stored player's idle step runs a later epoch's whole input

Component: the PRT player and crisium main loop (`doc/recipes/prt.lua`, `doc/recipes/crisium.lua`). Role:
Support, standing in for the honest operator.

## What is asserted

`crisium.lua` observes the chain tip only between steps of its `idle()`. Each step calls every listener's
`player.event_handler.idle`. For the stored player, that is `stored_event_handler.idle` ->
`event_handler.idle` -> `run_next_input`, which calls `run_to_input_mcycle_offset(...,
MAX_MCYCLES_PER_ADVANCE_STATE)` and runs one pending input of the open epoch to its fixed point in a single
call. No event of the sealed epoch's dispute is observed or answered until that call returns, so the delay
grows with the input's mcycle count, up to the per-input limit of 2^48 mcycles.

The test uses the recipe unchanged. It builds a bare-metal template whose correctly designed guest spins for
the number of iterations its input names and then accepts with the empty outputs root (`guest.c`). It opens
two stored players as crisium has them: epoch e sealed and epoch e+1 open. It adds one input to epoch e+1
through `input_added`, which only records the input, and then runs exactly one crisium `idle()` step, which
is the work crisium does between two tip observations. It measures the epoch machine's mcycle before and
after that step.

- Control: a short input (2^20 mcycles) runs whole in one step.
- Assertion: a long input (2^27 mcycles) must **not** run whole in one step. That means the machine advances
  fewer mcycles than the input needs, and the input is still pending or partly done. The work of each step
  has to be bounded and must not grow with the input's length.

The second path the candidate names, the agreed-pair replay (`advance_agreed_pair` replays one whole input per
idle step), has the same structure. This test does not exercise it.

## Requirement

THREAT_MODEL.md, R4:

> The honest operator observes the chain and submits its transactions within the dispute clocks.
>
> The honest operator defends every epoch whose dispute is open, including while it processes the inputs of
> later epochs.

The recipe's own comment, at `stored_event_handler` in `prt.lua`, makes a claim that this test contradicts:

> A stored player only records its inputs and runs them in idle time, so an open epoch never delays a response
> in a sealed epoch's dispute.

## Run

```sh
bugs/run.sh R1-A7-3        # about 10 s; temp files go under $TMPDIR (default /tmp) and are removed
```

`guest.bin` (2 KB) is the built `guest.c`. `build-guest.sh` rebuilds it with the harness bare-metal builder
(docker).

## Expected output on audit/prt2 (exit 1)

```
short input (needs >= 1048576 mcycles): one idle step advanced 1048797 mcycles in 0.21 s CPU, ran it whole: true
long input (needs >= 134217728 mcycles): one idle step advanced 134217948 mcycles in 3.26 s CPU, ran it whole: true
per-step work ratio long/short: 128.0 (input length ratio 128); at the same rate, one step of an input at the 2^48-mcycle limit would take about 79 days
VIOLATED: R4: ... one idle step (between two tip observations of crisium.lua) must not run a later epoch's whole input of 134217728 mcycles (advanced 134217948)
run.sh: R1-A7-3: exit 1 (bug present)
```

The verdict depends only on the mcycle counts, which are deterministic. The CPU times are for information.
