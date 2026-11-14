# R6-DYNBRIDGE-3: the player's WebSocket head subscription blocks with no timeout once a frame has started

Component: `doc/recipes/prt-websocket.lua` `methods:receive` (used by `subscription_methods:wait`), which
`doc/recipes/crisium.lua`'s idle branch calls as `heads:wait(poll_interval)` when `--ws` is given. Role: Support
(the PRT player), standing in for the honest operator's chain observation.

`receive(timeout)` applies `timeout` only to the first byte of a frame. After that it calls `self.tcp:settimeout(nil)`
(line 87, "Once a message starts, the rest is read without a timeout") and blocks until the frame completes or the
socket fails. The socket has no keepalive. A connection that stalls mid-frame without FIN/RST (a stalled proxy,
half-open TCP) therefore keeps crisium's single thread inside `wait` for as long as the stall lasts. Nothing is raised,
so `prt-supervise.sh` has no exit to relaunch, and the player stops reading the tip, ticking and submitting.

## What the test asserts

`test.lua` runs two processes on 127.0.0.1 (`peer.lua`): a fake node that completes the RFC 6455 handshake and the
`eth_subscribe` reply, and the real `prt-websocket` client (`new_head_subscription` then `heads:wait(1)`, as crisium
calls it with its default poll interval of 1 s).

* Control: the node starts no further frame. `wait(1)` must return nil within 3 s. If it does not, the test exits 2.
* Stall: the node sends one byte (`0x81`, the start of a text frame), then keeps the connection open for 30 s without
  sending anything. Asserted: `wait(1)` returns, with a header, nil or an error, within 3 s. The client is killed after
  10 s. A client that is still blocked at that point is the violation, and the test exits 1.

Requirement (THREAT_MODEL.md R4): "The honest operator observes the chain and submits its transactions within the
dispute clocks. After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim."
crisium.lua's own contract for this call: "with --ws it waits for the node to push the next header, and reads the tip
itself at least once per poll interval in case a header was missed."

Note for the reviewer: the trigger is a network fault between the player and its own node. Section 4 trusts the
operator's node, and it says "A host fault ... may stop the honest operator". The test shows only the code fact, a
transient stall that becomes an unbounded and silent block. It does not decide which reading applies.

## Run

```sh
bugs/run.sh R6-DYNBRIDGE-3      # about 12 s
```

Expected on audit/prt2:

```
[silent] client output: returned 1.000 true nil | status=0 |
control: wait(1) with no frame returned nil after 1.000 s
[mid-frame] client output: status=124 |
mid-frame stall: wait(1) still blocked after 10 s, killed (status 124)
VIOLATED: R4 ... must return within 3 s (it returned after more than 10 s, still blocked) ...
run.sh: R6-DYNBRIDGE-3: exit 1 (bug present)
```

(A `Terminated` line from the shell that ran the killed fake node is expected.)

I checked the opposite case against a scratch copy of `prt-websocket.lua` that keeps the timeout for the rest of
the frame (`self.tcp:settimeout(timeout or nil)` on line 87). There `wait(1)` raises `timeout` after 1.3 s and
the test exits 0.
