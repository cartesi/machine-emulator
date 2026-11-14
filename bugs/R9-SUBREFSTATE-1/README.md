# R9-SUBREFSTATE-1: the referee model stops accepting committed outputs

Component: the PRT referee model in `doc/recipes` (`prt.lua` `wait_for_outputs` over `game-transport.lua`
`request_first_valid` / `dispatch_request` / `accept_scheduled_response` / `step_time`).

## What is asserted

A5 (THREAT_MODEL.md): "Conversely, the referee accepts every output that the settled state commits to, whenever
its valid proof is presented. No party can make it stop accepting them."

`test.lua` runs the shipped `wait_for_outputs` (taken from `require("prt")` closures) on the shipped referee
transport (`prtu.new_server`), driving the transport's own loop (`step_time` + dispatcher steps) in process:

1. Settled state: the harness `baremetal-template` (a valid template, `emit-output.bin`) after two accepted advance
   inputs. It commits to outputs 0 and 1; the outputs-root proof (iflags_Y, htif_tohost, tx-buffer words) and both
   output proofs are built with the emulator and checked first with the model's own validators (`game-output.lua`).
2. The honest player answers as `prt.lua`'s `event_handler.prove_output` does: it always offers the epoch's last
   output (output 1). Output 1 is accepted; its repeated offer of output 1 is refused.
3. A party then connects and presents a valid proof of output 0 (it answers `prove_output` with it and would also push
   it under the request id in `advance_time` replies).
4. The loop runs until quiescent (no runnable coroutine, no logical-time progress, no socket readiness for 1 s on
   loopback) or a step budget. The test requires that output 0 has been accepted.

A control scenario runs first in the same process: with the presenter connected before settlement, the same
players, proofs and driver get output 0 accepted. If the control fails the test exits 2.

Why it fails: `request_first_valid(EVERYONE, prove_output, ...)` fixes its audience to the players connected when the
request is issued; once every audience member has answered without a new valid proof, no logical-time boundary
remains, so the clock never advances, no new request is issued and no `advance_time` is sent. A later presenter is
never asked anything, and an answer outside the audience would be dropped (`accept_scheduled_response`).

## Run

```sh
bugs/run.sh R9-SUBREFSTATE-1
```

Needs the in-tree build and `bugs/harness/work/configs/baremetal-template`. Takes about 3 s.

## Expected output on audit/prt2 (exit 1)

```
referee accepted output 1
referee accepted output 0
[control] phase 1: condition at block 3; honest asked prove_output 2 times; accepted {1,0}
[control] presenter got 6 events (prove_output 2, advance_time 3); accepted {1,0}
referee accepted output 1
[late] phase 1: quiescent at block 3; honest asked prove_output 2 times; accepted {1}
[late] phase 2: quiescent; block 3 -> 3; presenter connected=true
[late] presenter got 0 events (prove_output 0, advance_time 0); accepted {1}
VIOLATED: A5: the referee accepts every output that the settled state commits to, whenever its valid proof is presented; ...
run.sh: R9-SUBREFSTATE-1: exit 1 (bug present)
```

Exit 0 once a valid proof of a committed output presented after the referee's audience has been exhausted is
accepted.
